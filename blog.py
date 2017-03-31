"""
Web app handler for Porfolio.

This module performs the handling for the Portfolio project of Tabitha Jarvis,
as specified in Udacity's Front-End Development course.  This currently
includes only the blog project.

Example:
  To run this module locally, run the following::

    $ dev_appserver.py app.yaml

  To run locally with debug messages, run the following::

    $ dev_appserver.py --log_level debug app.yaml

  Or go to the deployed app at:

    https://blog-161405.appspot.com

"""

import os
import re
import hmac
import logging
from datetime import datetime
from functools import wraps

import webapp2
import jinja2

from google.appengine.ext import db

# Hash salt.  Do not change.
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
    """Retrieve the base post key."""
    return db.Key.from_path('Post', name)


def user_key(name='default'):
    """Retrieve the base user key."""
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


# Decorator Fucntions #########################################################

def login_required(f):
    """Wrap functions that require login with login check."""
    @wraps(f)
    def wrapper(self):
        username = self.get_cookie("username")
        password = self.get_cookie("password")
        user = find_by_name(username)
        if user and password == user.password:
            return f(self)
        else:
            logging.debug("\nUser: %s\nPassword: %s\n" % (username, password))
            error = "You must be logged in to perform this action."
            self.redirect_to('SignIn', error=error)
    return wrapper


def post_exists(f):
    """Wrap functions that occur on a post id to verify post existance."""
    @wraps(f)
    def wrapper(self, **kw):
        key = db.Key.from_path(
            'Post',
            int(kw['post_id']),
            parent=post_key()
            )
        post = db.get(key)
        if post:
            return f(self, **kw)
        else:
            self.error(404)
            return
    return wrapper


def owns_post(f):
    """Wrap functions on posts intended to be used by owners."""
    @wraps(f)
    def wrapper(self, **kw):
        key = db.Key.from_path(
            'Post',
            int(kw["post_id"]),
            parent=post_key()
            )
        post = db.get(key)

        username = self.get_cookie("username")
        password = self.get_cookie("password")
        user = find_by_name(username)

        if not post:
            self.error(404)
            return
        elif not (user and password == user.password):
            error = "You must be logged in to perform this action."
            self.redirect_to('SignIn', error=error)
        elif not user.username == post.author.username:
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            return f(self, **kw)
    return wrapper


def owns_comment(f):
    """Wrap functions on comment actions intended to be used by owners."""
    @wraps(f)
    def wrapper(self, **kw):
        p_key = db.Key.from_path(
            'Post',
            int(kw["post_id"]),
            parent=post_key()
            )
        post = db.get(p_key)
        if not post:
            self.error(404)
            return

        c_key = db.Key.from_path(
            'Comment',
            int(kw["comment_id"]),
            parent=p_key
        )
        comment = db.get(c_key)
        if not comment:
            self.error(404)
            return

        username = self.get_cookie("username")
        password = self.get_cookie("password")
        user = find_by_name(username)

        if not (user and password == user.password):
            error = "You must be logged in to perform this action."
            self.redirect_to('SignIn', error=error)
        elif not user.username == comment.author.username:
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            return f(self, **kw)
    return wrapper


# Base Handler ################################################################

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


# Page Handlers ###############################################################

class MainPage(Handler):
    """The handler for the main page of the portfolio."""

    def get(self):
        """Render the home page."""
        self.render('index.html')


class Blog(Handler):
    """The handler for the blog project of the porfolio.

    This is the home page of the blog project.  This page lists the 10 most
    recent blog entries.
    """

    def get(self):
        """Get the front page with the 10 newest blog posts."""
        # Retrieve the 10 most recent posts
        posts = db.GqlQuery(
            "select * from Post order by created desc limit 10"
            )

        # Get any locally cached info for quick local updates.  This
        # compensates for database updates being slower than database reads.
        cached_type = self.get_cookie("cached_type")
        cached_key = self.get_cookie("cached_key")
        cached_data = self.get_cookie("cached_data")

        logging.debug("\nCached Type is: %s\n" % cached_type)

        # If "Vote Post" is cached, locally set the score of that post.
        if cached_type == "VotePost" and int(cached_key) in posts:
            posts[int(cached_key)].score = int(cached_data)
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        # If "Delete Post" is cached, remove post locally.
        elif cached_type == "DeletePost" and int(cached_key) in posts:
            del posts[int(cached_key)]
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        self.render(
            'blog.html',
            posts=posts,
            username=self.get_cookie("username")
            )

    @login_required
    def post(self):
        """Handle the POST action."""
        # Currently, the only post option on the blog post is voting.
        # Get the post to vote on
        key = db.Key.from_path(
            'Post',
            int(self.request.get("vote_post")),
            parent=post_key()
            )
        vote_item = db.get(key)

        # Get the vote value (Upvote/Downvote) and the username
        vote = self.request.get("vote")
        username = self.get_cookie("username")

        # Attempt to upvote or downvote
        if vote == "Upvote":
            vote_item.upvote(username)
        elif vote == "Downvote":
            vote_item.downvote(username)
        vote_item.put()

        # Set vote cache for immediate local update
        self.set_cookie("cached_type", "VotePost")
        self.set_cookie("cached_key", str(vote_item.key().id()))
        self.set_cookie("cached_data", str(vote_item.score))
        self.redirect_to('Blog')


class Permalink(Handler):
    """Handle the individual blog entry pages.

    This page gets an individual post, and shows all comments for that post
    as well as a comment entry box.
    """

    @post_exists
    def get(self, **kw):
        """Get the post entry page from the url."""
        # Get the post from the URL
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        # Get cached data
        cached_key = self.get_cookie("cached_key")
        cached_type = self.get_cookie("cached_type")
        cached_data = self.get_cookie("cached_data")

        # If a vote button was pressed, ensure it updates locally quickly
        if cached_type == "VotePost":
            post.score = int(cached_data)
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        # If a new comment was just added, ensure that it updates the user
        elif cached_type == "NewComment" and int(cached_key) in post.comments:
            cached_comment = db.get(cached_key)
            if cached_comment:
                cached_comment.author.username = cached_data
                self.set_cookie("cached_key", "")
                self.set_cookie("cached_type", "")
                self.set_cookie("cached_data", "")

        # If a vote button was pressed, ensure it updates locally quickly
        elif cached_type == "VoteComment" and int(cached_key) in post.comments:
            post.comments[int(cached_key)].score = int(cached_data)
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        # If a comment is deleted, ensure it is removed locally quickly
        elif cached_type == "DeleteComment" and db.get(cached_key):
            del post.comments['cached_key']
            self.set_cookie("cached_type", "")
            self.set_cookie("cached_key", "")
            self.set_cookie("cached_data", "")

        # Get post's comments by highest score, then date
        comments = db.Query(Comment).ancestor(key)
        comments = comments.order('-score').order('-created')

        return self.render(
            "permalink.html",
            post=post,
            comments=comments,
            username=self.get_cookie("username")
            )

    @owns_post
    def post(self, **kw):
        """Save comment in the database."""
        # Get post from URL
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        # Get username
        user = find_by_name(self.get_cookie('username'))

        # Call correct function for which form was called
        if self.request.get('vote_post'):
            return self.vote_post(user, post)

        if self.request.get('add_comment'):
            return self.add_comment(user, post)

        if self.request.get('delete_comment'):
            return self.delete_comment(user, post)

        if self.request.get('vote_comment'):
            return self.vote_comment(user, post)

    def vote_post(self, user, post):
        """Vote on post if logged in and not author."""
        # Get vote value (Upvote/Downvote)
        vote = self.request.get("vote")

        # If user is not the post's author, handle vote
        if user.username != post.author.username:
            if vote == "Upvote":
                post.upvote(user.username)
            elif vote == "Downvote":
                post.downvote(user.username)
            post.put()
            # Store vote score for quick local updating
            self.set_cookie("cached_type", "VotePost")
            self.set_cookie("cached_key", str(post.key().id()))
            self.set_cookie("cached_data", str(post.score))

            self.redirect('/blog/%s' % str(post.key().id()))

    def add_comment(self, user, post):
        """Add comment if logged in."""
        comment = self.request.get('comment')

        if not comment:
            return self.redirect('/blog/%s' % str(post.key().id()))

        else:
            # Add new comment, and put author's name in local cache
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
        # Get comment to vote on by comment ID
        key = db.Key.from_path(
            'Comment',
            int(self.request.get("vote_comment")),
            parent=post.key()
            )
        vote_item = db.get(key)

        # Get vote value (Upvote/Downvote)
        vote = self.request.get("vote")

        # If the user is not the author of the comment, attempt to vote
        if user.username != vote_item.author.username:
            if vote == "Upvote":
                vote_item.upvote(user.username)
            elif vote == "Downvote":
                vote_item.downvote(user.username)
            vote_item.put()
            # Store vote score for quick local updating
            self.set_cookie("cached_type", "VoteComment")
            self.set_cookie("cached_key", str(vote_item.key().id()))
            self.set_cookie("cached_data", str(vote_item.score))

        self.redirect('/blog/%s' % str(post.key().id()))

    def delete_comment(self, user, post):
        """Delete comment if author."""
        # Get comment to delete
        key = db.Key.from_path(
            'Comment',
            int(self.request.get("delete_comment")),
            parent=post.key()
            )
        comment = db.get(key)

        # If user is the comment's author, allow deletion
        if str(user.username) == str(comment.author.username):
            # Set deleted comment info to local cache
            self.set_cookie("cached_type", "DeleteComment")
            self.set_cookie("cached_key", str(key.id()))
            self.set_cookie("cached_data", str(comment.author.username))
            comment.delete()

        self.redirect('/blog/%s' % str(post.key().id()))


class NewPost(Handler):
    """Handle the new post entry page."""

    @login_required
    def get(self):
        """Get the new post page."""
        self.render('newpost.html')

    @login_required
    def post(self):
        """Save post in the database if valid, or prompt for valid entry."""
        title = self.request.get('title')
        blogpost = self.request.get('blogpost')
        author = find_by_name(self.get_cookie('username'))

        # Create new posts if fields are filled out
        if title and blogpost:
            p = Post(
                parent=post_key(),
                author=author,
                title=title,
                blogpost=blogpost
                )
            p.put()
            # Redirect to the new post's page
            return self.redirect('/blog/%s' % str(p.key().id()))
        # Prompt for field entry
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

    @owns_post
    def get(self, **kw):
        """Get the blog edit page from the url."""
        # Get post from URL
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        self.render(
            'editpost.html',
            title=post.title,
            blogpost=post.blogpost,
            post_id=kw['post_id']
            )

    @owns_post
    def post(self, **kw):
        """Update the blog post."""
        # Get the post from the URL
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        # Get the username and fields
        username = self.get_cookie('username')
        title = self.request.get('title')
        blogpost = self.request.get('blogpost')

        # Ensure that the fields are filled out
        if title and blogpost:
            # Edit the post
            post.title = title
            post.blogpost = blogpost
            post.last_modified = datetime.now()
            post.put()
            return self.redirect('/blog/%s' % kw['post_id'])
        else:
            error = "Please enter a title and post content."
            return self.render(
                'editpost.html',
                post=post,
                error=error
                )


class EditComment(Handler):
    """Handle the edit comment pages."""

    @owns_comment
    def get(self, **kw):
        """Get the blog edit page from the url."""
        # Get the post and comment from the URL
        p_key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(p_key)
        c_key = db.Key.from_path(
            'Comment',
            int(kw['comment_id']),
            parent=p_key
            )
        comment = db.get(c_key)

        self.render(
            'editcomment.html',
            post=post,
            comment=comment.comment,
            comment_id=kw['comment_id']
            )

    @owns_comment
    def post(self, **kw):
        """Update the comment."""
        # Get post and comment from the URL
        p_key = db.Key.from_path(
            'Post',
            int(kw['post_id']),
            parent=post_key()
            )
        post = db.get(p_key)
        c_key = db.Key.from_path(
            'Comment',
            int(kw['comment_id']),
            parent=p_key
            )
        comm = db.get(c_key)

        # Get username and edited comment.
        username = self.get_cookie('username')
        comment = self.request.get('comment')

        # Ensure that the new comment exists
        if comment:
            comm.comment = comment
            comm.last_modified = datetime.now()
            comm.put()
            return self.redirect('/blog/%s' % kw['post_id'])
        else:
            error = "Please enter a comment."
            return self.render(
                'editpost.html',
                post=post,
                error=error
                )


class DeletePost(Handler):
    """Handle the delete blog post page."""

    @owns_post
    def get(self, **kw):
        """Get the delete post confirmation page."""
        # Get the post from the URL
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        # Display the confirmation page
        self.render(
            'deletepost.html',
            post=post
            )

    @owns_post
    def post(self, **kw):
        """Delete the post."""
        # Get the post from the URL
        key = db.Key.from_path('Post', int(kw['post_id']), parent=post_key())
        post = db.get(key)

        # Delete the post
        post.delete()

        return self.redirect_to('Deleted')


class Deleted(Handler):
    """Handler for successful delete message page."""

    def get(self):
        """Display delete successful message."""
        return self.render('deletesuccessful.html')


class SignUp(Handler):
    """Handle the sign up page."""

    def get(self):
        """Get the sign up form document."""
        self.render("signup-form.html")

    def post(self):
        """Store username cookie if all form info is valid."""
        # Get the form info
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        error_flag = False

        # Initialize params
        params = {"username": username, "email": email}

        # Check for valid username that is unique
        if not valid_username(username):
            params['error_username'] = "Please enter a valid username."
            error_flag = True
        elif find_by_name(username):
            params['error_username'] = "This username is not available."
            error_flag = True

        # Check for valid password and that it matches the verify password
        if not valid_password(password):
            params['error_password'] = "Please enter a valid password."
            error_flag = True
        elif password != verify:
            params['error_verify'] = "Your passwords did not match."
            error_flag = True

        # Check for valid email
        if not valid_email(email):
            params['error_email'] = "Please enter a valid email address."
            error_flag = True

        # If there were any errors, return this page with errors
        if error_flag:
            self.render('signup-form.html', **params)

        # Otherwise, create a new user and go to the home page
        else:
            user = User(
                parent=user_key(),
                username=username,
                password=password,
                email=email
                )
            user.put()
            self.set_cookie("username", username)
            self.set_cookie("password", password)
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
        # Get the form info
        username = self.request.get('username')
        password = self.request.get('password')
        error_flag = False

        # Initialize params
        params = {"username": username}

        user = find_by_name(username)

        # Check if user exists and if the password is correct for that user
        if not user:
            params['error_username'] = "Username does not exist."
            error_flag = True
        elif not user.password == password:
            params['error_password'] = "Incorrect password."
            error_flag = True

        # If there were errors, return this page with the errors
        if error_flag:
            self.render('signin-form.html', **params)

        # Otherwise, log the user in.
        else:
            self.set_cookie("username", username)
            self.set_cookie("password", password)
            return self.redirect_to('Blog')


class LogOut(Handler):
    """Handler for logging out."""

    def get(self):
        """Clear cookies and redirect to sign in."""
        self.set_cookie("username", "")
        self.set_cookie("password", "")
        return self.redirect_to('SignIn', error="Successfully logged out.")


class User(db.Model):
    """User entities."""

    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)


class Post(db.Model):
    """Post entities and blog post rendering."""

    # Set an "author" user property
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

    # User lists for upvotes/downvotes on a post
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

        # Upvote if user hasn't upvoted and isn't the post's author
        if key not in self.upvotes and username != self.author.username:
            # If user has downvoted, remove them from the downvote list
            if key in self.downvotes:
                self.downvotes.remove(key)
            # Otherwise, add to the upvote list
            else:
                self.upvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()

    def downvote(self, username):
        """Handle this post's downvote action."""
        key = user_key(username)

        # Downvote if a user hasn't downvoted and isn't the post's author
        if key not in self.downvotes and username != self.author.username:
            # If a user has upvoted, remove them from the upvote list
            if key in self.upvotes:
                self.upvotes.remove(key)
            # Otherwise, add to the downvote list
            else:
                self.downvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()


class Comment(db.Model):
    """Comment entities."""

    # Set a "post" post property
    post = db.ReferenceProperty(
        Post,
        collection_name="comments",
        required=True
        )

    # Set an "author" user property
    author = db.ReferenceProperty(
        User,
        collection_name="comments",
        required=True
        )

    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    score = db.IntegerProperty(default=0)

    # User lists for upvotes/downvotes
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

        # Upvote if user hasn't upvoted and isn't the comment's author
        if key not in self.upvotes and username != self.author.username:
            # If user has downvoted, remove them from the downvote list
            if key in self.downvotes:
                self.downvotes.remove(key)
            # Otherwise, add to the upvote list
            else:
                self.upvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()

    def downvote(self, username):
        """Handle this post's downvote action."""
        key = user_key(username)

        # Downvote if user hasn't upvoted and isn't the comment's author
        if key not in self.downvotes and username != self.author.username:
            # If user has upvoted, remove them from the upvote list
            if key in self.upvotes:
                self.upvotes.remove(key)
            # Otherwise, add to the downvote list
            else:
                self.downvotes.append(key)
            self.score = len(self.upvotes) - len(self.downvotes)
            self.put()


app = webapp2.WSGIApplication([
    webapp2.Route(
        '/',
        MainPage,
        'MainPage'
        ),

    webapp2.Route(
        '/blog',
        Blog,
        'Blog'
        ),

    webapp2.Route(
        '/blog/newpost',
        NewPost,
        'NewPost'
        ),

    webapp2.Route(
        '/blog/<post_id:([0-9]+)>',
        Permalink,
        'Permalink'
        ),

    webapp2.Route(
        '/blog/<post_id:([0-9]+)>/edit',
        EditPost,
        'EditPost'
        ),

    webapp2.Route(
        '/blog/<post_id:([0-9]+)>/delete',
        DeletePost,
        'DeletePost'
        ),

    webapp2.Route(
        '/blog/<post_id:([0-9]+)>/<comment_id:([0-9]+)>/edit',
        EditComment,
        'EditComment'
        ),

    webapp2.Route(
        '/blog/deletesuccessful',
        Deleted,
        'Deleted'
        ),

    webapp2.Route(
        '/blog/signin',
        SignIn,
        'SignIn'
        ),

    webapp2.Route(
        '/blog/signup',
        SignUp,
        'SignUp'
        ),

    webapp2.Route(
        '/blog/logout',
        LogOut,
        'LogOut'
        ),

    ], debug=True)
