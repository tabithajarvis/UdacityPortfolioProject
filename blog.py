"""
Web app handler for Porfolio.

This module performs the handling for the Portfolio project of Tabitha Jarvis,
as specified in Udacity's Front-End Development course.  This currently
includes only the blog project.

Example:
  To run this module locally, run the following::

    $ dev_appserver.py app.yaml

  Or go to the deployed app at:

    https://blog-161405.appspot.compile

TODO:
  - Delete own posts
  - Like/Unlike posts except own
    - Error trying to like own post
  - Comment on posts
    - Edit own comments
    - Delete own comments
"""

import os
import re
import hmac
import logging
from datetime import datetime

import webapp2
import jinja2

from google.appengine.ext import db

secret = 'l0ng_&secure.$A1t-4_#ing'

# Set up Jinja2 enviroment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Input and character restrictions for username, password, and email
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{6,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def render_str(template, **kwargs):
    """Render a jinja2 template."""
    t = jinja_env.get_template(template)
    return t.render(kwargs)


def post_key(name='default'):
    """Retrieve the blog key."""
    return db.Key.from_path('Post', name)


def user_key(name='default'):
    """Retrieve the user key."""
    return db.Key.from_path('User', name)


def valid_username(username):
    """Check if a username is valid."""
    return username and USER_RE.match(username)


def valid_password(password):
    """Check if a password is valid."""
    return password and PASS_RE.match(password)


def valid_email(email):
    """Check if an email address is valid."""
    return not email or EMAIL_RE.match(email)


def find_by_name(username):
    """Find a user by username."""
    user = db.GqlQuery(
        "select * from User where username = :username",
        username=username
        )
    return user.get()


def make_secure_val(val):
    """Create a salted hash password for cookie storage."""
    return '%s|%s' % (val, hmac.new(secret, str(val)).hexdigest())


def check_secure_val(secure_val):
    """Check that the salt is correct."""
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Base handler
class Handler(webapp2.RequestHandler):
    """The generic handler for all web pages.

    All other web page handlers derive from this class.  This contains the
    functions for rendering the web pages and writing them to the client's
    browser.  It also contains cookie methods for creating, setting, and
    reading cookies from the client.
    """

    def write(self, *a, **kw):
        """Write the HTML."""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **kw):
        """Call the global render string function for rendering templates."""
        return render_str(template, **kw)

    def render(self, template, **kw):
        """Render the template given."""
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, value):
        """Set a cookie."""
        secure_val = make_secure_val(value)
        self.response.headers['Set-Cookie'] = \
            str("%s=%s; Path=/;" % (name, secure_val))

    def get_cookie(self, name):
        """Get a cookie."""
        value = self.request.cookies.get(name)
        if value:
            return check_secure_val(value)


# Page Handlers
class MainPage(Handler):
    """The handler for the main page of the portfolio."""

    def get(self):
        """Render the home page."""
        self.render('index.html')


class Blog(Handler):
    """The handler for the blog project of the porfolio.

    This is the home page of the blog project.
    """

    def get(self):
        """Get the front page with the 10 newest blog posts."""
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10"
            )

        # Get any locally cached info for quick local updates.  This
        # compensates for database updates being slower than database reads.
        cached_type = self.get_cookie("cached_type")
        cached_key = self.get_cookie("cached_key")
        cached_data = self.get_cookie("cached_data")

        logging.debug("\n\nCached Type is: %s\n\n" % cached_type)

        # If "Vote Post" is cached, locally set the score of that post.
        if cached_type == "VotePost" and int(cached_key) in posts:
            posts[int(cached_key)].score = int(cached_data)
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        # If "Delete Post" is cached, remove post locally.
        elif cached_type == "DeletePost" and int(cached_key) in posts:
            logging.debug("\n\n Cookie reading is all good \n\n")
            del posts[int(cached_key)]
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        self.render(
            'blog.html',
            posts=posts,
            username=self.get_cookie("username")
            )

    def post(self):
        """Handle the POST action."""
        # Currently, the only post option on the blog post is voting.
        key = db.Key.from_path(
            'Post',
            int(self.request.get("vote_id")),
            parent=post_key()
            )
        vote_item = db.get(key)
        vote = self.request.get("vote")
        username = self.get_cookie("username")

        if username != "":
            if vote == "Upvote":
                vote_item.upvote(username)
            elif vote == "Downvote":
                vote_item.downvote(username)
            vote_item.put()
            self.set_cookie("cached_type", "VotePost")
            self.set_cookie("cached_key", str(vote_item.key().id()))
            self.set_cookie("cached_data", str(vote_item.score))

        self.redirect_to('Blog')


class PostPage(Handler):
    """Handle the individual blog entry pages.

    This page gets an individual post, and shows all comments for that post
    as well as a comment entry box.
    """

    def get(self, **kw):
        """Get the post entry page from the url."""
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)
        if not post:
            logging.debug("\n404 Page Not Found\n")
            self.error(404)

        cached_key = self.get_cookie("cached_key")
        cached_type = self.get_cookie("cached_type")
        cached_data = self.get_cookie("cached_data")

        if cached_type == "NewComment" and db.get(cached_key):
            cached_comment = db.get(cached_key)
            if cached_comment:
                cached_comment.author.username = cached_data
                self.set_cookie("cached_key", "")
                self.set_cookie("cached_type", "")
                self.set_cookie("cached_data", "")
        elif cached_type == "VoteComment" and int(cached_key) in post.comments:
            post.comments[int(cached_key)].score = int(cached_data)
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")
        elif cached_type == "DeleteComment" and db.get(cached_key):
            del post.comments['cached_key']
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        return self.render(
            "permalink.html",
            post=post,
            username=self.get_cookie("username")
            )

    def post(self, **kw):
        """Save comment in the database."""
        user = find_by_name(self.get_cookie('username'))
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        if self.request.get('add_comment'):
            return self.add_comment(user, post)

        if self.request.get('delete_comment'):
            return self.delete_comment(user, post)

        if self.request.get('vote_comment'):
            return self.vote_comment(user, post)

    def add_comment(self, user, post):
        """Add comment if logged in."""
        comment = self.request.get('comment')
        if not user:
            error = "You must be logged in to comment."
            return self.render(
                "permalink.html",
                post=post,
                error=error
                )

        if not comment:
            error = "Your comment cannot be empty."
            return self.render(
                "permalink.html",
                post=post,
                error=error
                )

        else:
            c = Comment(
                parent=post.key(),
                post=post,
                author=user,
                comment=comment
                )
            c.put()
            self.set_cookie("cached_type", "NewComment")
            self.set_cookie("cached_key", str(c.key().id()))
            self.set_cookie("cached_data", str(c.author.username))
            return self.redirect('/blog/%s' % str(post.key().id()))

    def vote_comment(self, user, post):
        """Vote on comment if logged in and not author."""
        key = db.Key.from_path(
            'Comment',
            int(self.request.get("vote_comment")),
            parent=post.key()
            )
        vote_item = db.get(key)
        vote = self.request.get("vote")

        if user and user.username != vote_item.author.username:
            if vote == "Upvote":
                vote_item.upvote(user.username)
            elif vote == "Downvote":
                vote_item.downvote(user.username)
            vote_item.put()
            self.set_cookie("cached_type", "VoteComment")
            self.set_cookie("cached_key", str(vote_item.key().id()))
            self.set_cookie("cached_data", str(vote_item.score))
            self.redirect('/blog/%s' % str(post.key().id()))

    def delete_comment(self, user, post):
        """Delete comment if author."""
        key = db.Key.from_path(
            'Comment',
            int(self.request.get("delete_comment")),
            parent=post.key()
            )
        comment = db.get(key)
        if user and str(user.username) == str(comment.author.username):
            self.set_cookie("cached_type", "DeleteComment")
            self.set_cookie("cached_key", str(key.id()))
            self.set_cookie("cached_data", str(comment.author.username))
            comment.delete()
            self.redirect('/blog/%s' % str(post.key().id()))



class NewPost(Handler):
    """Handle the new post entry page."""

    def get(self):
        """Get the new post page."""
        self.username = self.get_cookie('username')

        if self.username:
            self.render('newpost.html')
        else:
            error = "You must be signed in to create posts."
            return self.redirect_to('SignIn', error=error)

    def post(self):
        """Save post in the database if valid, or prompt for valid entry."""
        title = self.request.get('title')
        blogpost = self.request.get('blogpost')
        author = find_by_name(self.get_cookie('username'))

        if title and blogpost:
            p = Post(
                parent=post_key(),
                author=author,
                title=title,
                blogpost=blogpost
                )
            p.put()
            return self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Please enter a title and post content."
            self.render(
                'newpost.html',
                title=title,
                blogpost=blogpost,
                error=error
                )


class EditPost(Handler):
    """Handle the edit blog pages."""

    def get(self, **kw):
        """Get the blog edit page from the url."""
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)
        username = self.get_cookie('username')
        if username == post.author.username:
            self.render(
                'editpost.html',
                title=post.title,
                blogpost=post.blogpost,
                post_id=kw['post_id']
                )
        else:
            return self.redirect('/blog/%s' % kw['post_id'])

    def post(self, **kw):
        """Update the blog post."""
        username = self.get_cookie('username')
        title = self.request.get('title')
        blogpost = self.request.get('blogpost')

        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        if post and username:
            if username == post.author.username:
                if title and blogpost:
                    post.title = title
                    post.blogpost = blogpost
                    post.last_modified = datetime.now()
                    post.put()
                    return self.redirect('/blog/%s' % kw['post_id'])
                else:
                    error = "Please enter a title and post content."
            else:
                error = "You are not authorized to edit this post."
        else:
            error = "Cannot access post."

        self.render(
            'editpost.html',
            post=post,
            error=error
            )


class EditComment(Handler):
    """Handle the edit comment pages."""

    def get(self, **kw):
        """Get the blog edit page from the url."""
        p_key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(p_key)
        c_key = db.Key.from_path('Comment', int(kw['comment_id']), parent=p_key)
        comment = db.get(c_key)
        username = self.get_cookie('username')
        if username == comment.author.username:
            self.render(
                'editcomment.html',
                post=post,
                comment=comment.comment,
                comment_id=kw['comment_id']
                )
        else:
            return self.redirect('/blog/%s' % kw['post_id'])

    def post(self, **kw):
        """Update the comment."""
        username = self.get_cookie('username')
        comment = self.request.get('comment')

        p_key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(p_key)
        c_key = db.Key.from_path('Comment', int(kw['comment_id']), parent=p_key)
        comm = db.get(c_key)

        if post and comm and username:
            if username == comm.author.username:
                if comment:
                    comm.comment = comment
                    comm.last_modified = datetime.now()
                    comm.put()
                    return self.redirect('/blog/%s' % kw['post_id'])
                else:
                    error = "Please enter an edited comment."
            else:
                error = "You are not authorized to edit this comment."
        else:
            error = "Cannot access comment."

        self.render(
            'editpost.html',
            post=post,
            error=error
            )


class DeletePost(Handler):
    """Handle the delete blog post page."""

    def get(self, **kw):
        """Get the delete post confirmation page."""
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)
        username = self.get_cookie('username')
        if post and username == post.author.username:
            self.render(
                'deletepost.html',
                post=post
                )
        else:
            return self.redirect_to('Blog')

    def post(self, **kw):
        """Delete the post."""
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)
        post.delete()

        return self.redirect_to('Deleted')


class Deleted(Handler):
    """Handler for successful delete message page."""

    def get(self):
        """Display delete successful message"""
        return self.render('deletesuccessful.html', type="Post")


class SignUp(Handler):
    """Handle the sign up page."""

    def get(self):
        """Get the sign up form document."""
        self.render("signup-form.html")

    def post(self):
        """Store username cookie if all form info is valid."""
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        error_flag = False

        params = {"username": username, "email": email}

        if not valid_username(username):
            params['error_username'] = "Please enter a valid username."
            error_flag = True
        elif find_by_name(username):
            params['error_username'] = "This username is not available."
            error_flag = True

        if not valid_password(password):
            params['error_password'] = "Please enter a valid password."
            error_flag = True
        elif password != verify:
            params['error_verify'] = "Your passwords did not match."
            error_flag = True

        if not valid_email(email):
            params['error_email'] = "Please enter a valid email address."
            error_flag = True

        if error_flag:
            self.render('signup-form.html', **params)
        else:
            user = User(
                parent=user_key(),
                username=username,
                password=password,
                email=email
                )
            user.put()
            self.set_cookie("username", username)
            return self.redirect_to('Blog')


class SignIn(Handler):
    """Handle the sign in page."""

    def get(self):
        """Get the sign in form document."""
        self.render(
            "signin-form.html",
            error_action=self.request.get('error'),
            logged_out=self.request.get('logged_out')
            )

    def post(self, **kw):
        """Store username cookie if userame and password are correct."""
        username = self.request.get('username')
        password = self.request.get('password')
        error_flag = False

        params = {"username": username}

        user = find_by_name(username)

        if not user:
            params['error_username'] = "Username does not exist."
            error_flag = True
        elif not user.password == password:
            params['error_password'] = "Incorrect password."
            error_flag = True

        if error_flag:
            self.render('signin-form.html', **params)
        else:
            self.set_cookie("username", username)
            return self.redirect_to('Blog')


class LogOut(Handler):
    """Handler for logging out."""

    def get(self):
        """Clear cookies and redirect to sign in."""
        self.set_cookie("username", "")
        return self.redirect_to('SignIn', error="Successfully logged out.")


class User(db.Model):
    """User entities."""

    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)


class Post(db.Model):
    """Post entities and blog post rendering."""

    author = db.ReferenceProperty(
        User,
        collection_name="posts",
        required=True
        )

    title = db.StringProperty(required=True)
    blogpost = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    score = db.IntegerProperty(default=0)
    upvotes = db.ListProperty(db.Key)
    downvotes = db.ListProperty(db.Key)

    def render(self, **kwargs):
        """Render template replacing user-input new lines with line breaks."""
        self.blogpost = self.blogpost.replace('\n', '<br>')
        kwargs["post"] = self
        return render_str(
            "post.html",
            **kwargs
            )

    def upvote(self, username):
        """Handle this post's downvote action."""
        key = user_key(username)

        if key not in self.upvotes and username != self.author.username:
            if key in self.downvotes:
                self.downvotes.remove(key)
            else:
                self.upvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()

    def downvote(self, username):
        """Handle this post's downvote action."""
        key = user_key(username)

        if key not in self.downvotes and username != self.author.username:
            if key in self.upvotes:
                self.upvotes.remove(key)
            else:
                self.downvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()


class Comment(db.Model):
    """Comment entities."""

    post = db.ReferenceProperty(
        Post,
        collection_name="comments",
        required=True
        )

    author = db.ReferenceProperty(
        User,
        collection_name="comments",
        required=True
        )

    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    score = db.IntegerProperty(default=0)
    upvotes = db.ListProperty(db.Key)
    downvotes = db.ListProperty(db.Key)

    def render(self, **kw):
        """Render template replacing user-input new lines with line breaks."""
        self.comment = self.comment.replace('\n', '<br>')
        kw["comment"] = self

        return render_str(
            "comment.html",
            **kw
            )

    def upvote(self, username):
        """Handle this post's downvote action."""
        key = user_key(username)

        if key not in self.upvotes and username != self.author.username:
            if key in self.downvotes:
                self.downvotes.remove(key)
            else:
                self.upvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()

    def downvote(self, username):
        """Handle this post's downvote action."""
        key = user_key(username)

        if key not in self.downvotes and username != self.author.username:
            if key in self.upvotes:
                self.upvotes.remove(key)
            else:
                self.downvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()


app = webapp2.WSGIApplication([
    webapp2.Route('/', MainPage, 'MainPage'),
    webapp2.Route('/blog', Blog, 'Blog'),
    webapp2.Route('/blog/newpost', NewPost, 'NewPost'),
    webapp2.Route('/blog/<post_id:([0-9]+)>', PostPage, 'PostPage'),
    webapp2.Route('/blog/<post_id:([0-9]+)>/edit', EditPost, 'EditPost'),
    webapp2.Route('/blog/<post_id:([0-9]+)>/delete', DeletePost, 'DeletePost'),
    webapp2.Route('/blog/<post_id:([0-9]+)>/<comment_id:([0-9]+)>/edit', EditComment, 'EditComment'),
    webapp2.Route('/blog/deletesuccessful', Deleted, 'Deleted'),
    webapp2.Route('/blog/signin', SignIn, 'SignIn'),
    webapp2.Route('/blog/signup', SignUp, 'SignUp'),
    webapp2.Route('/blog/logout', LogOut, 'LogOut'),
    ], debug=True)
