"""
Web app handler for Porfolio.

This module performs the handling for the Portfolio project of Tabitha Jarvis,
as specified in Udacity's Front-End Development course.  This currently
includes only the blog project.

Example:
  To run this module locally, run the following::

    $ dev_appserver.py app.yaml

  Or go to the deployed app at::

    https://blog-161405.appspot.compile

"""

import os
import re

import webapp2
import jinja2

from google.appengine.ext import db

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


def blog_key(name='default'):
    """Retrieve the blog key."""
    return db.Key.from_path('blogs', name)


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

    def render_str(self, template, **params):
        """Call the global render string function for rendering templates."""
        return render_str(template, **params)

    def render(self, template, **kw):
        """Render the template given."""
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, value):
        """Set a cookie."""
        self.response.headers['Set-Cookie'] = \
            str("%s=%s; Path=/;" % (name, value))


# Page Handlers
class MainPage(Handler):
    """The handler for the main page of the portfolio."""

    def get(self):
        """Render the home page."""
        self.render('index.html')


class Blog(Handler):
    """The handler for the blog project of the porfolio.

    This is the home page of the blog project, and it requires a user to be
    logged in to access any of the pages.
    """

    def get(self):
        """Get the front page with the 10 newest blog posts."""
        p = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('blog.html', posts=p)

    def render(self, template, **kw):
        """Render blog pages if the username cookie is set."""
        username = self.request.cookies.get('username')

        if(template == "signup-form" or username):
            super(Blog, self).render(template, **kw)
        else:
            self.redirect('/blog/signup')


class NewPost(Handler):
    """Handle the new post entry page."""

    def get(self):
        """Get the new post page."""
        self.render('newpost.html')

    def post(self):
        """Save post in the database if valid, or prompt for valid entry."""
        title = self.request.get('title')
        blogpost = self.request.get('blogpost')

        if title and blogpost:
            p = Post(parent=blog_key(), title=title, blogpost=blogpost)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Please enter a title and post content."
            self.render(
                'newpost.html',
                title=title,
                blogpost=blogpost,
                error=error
                )


class PostPage(Handler):
    """Handle the individual blog entry pages."""

    def get(self, post_id):
        """Get the post entry page from the post id."""
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post, id=str(post.key().id()))


class SignupPage(Handler):
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

        params = dict(username=username, email=email)
        user = User(
            parent=blog_key(),
            username=username,
            password=password,
            email=email
            )

        if not user.valid_username(username):
            params['error_username'] = "Please enter a valid username."
            error_flag = True
        elif user.username_taken(username):
            params['error_username'] = "This username is not available."
            error_flag = True

        if not user.valid_password(password):
            params['error_password'] = "Please enter a valid password."
            error_flag = True
        elif password != verify:
            params['error_verify'] = "Your passwords did not match."
            error_flag = True

        if not user.valid_email(email):
            params['error_email'] = "Please enter a valid email address."
            error_flag = True

        if error_flag:
            self.render('signup-form.html', **params)
        else:
            user.put()
            self.set_cookie("username", username)
            self.redirect('/blog', username)


class Post(db.Model):
    """Handler for Post entities and blog post rendering."""

    title = db.StringProperty(required=True)
    blogpost = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        """Render template replacing user-input new lines with line breaks."""
        self.blogpost = self.blogpost.replace('\n', '<br>')
        return render_str("post.html", p=self, id=str(self.key().id()))


class User(db.Model):
    """Handler for User entities."""

    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

    def username_taken(self, username):
        """Check if a username has already been taken."""
        user = db.GqlQuery(
            "select * from User where username = :username",
            username=username
            )
        return user.get()

    def valid_username(self, username):
        """Check if a username is valid."""
        return username and USER_RE.match(username)

    def valid_password(self, password):
        """Check if a password is valid."""
        return password and PASS_RE.match(password)

    def valid_email(self, email):
        """Check if an email address is valid."""
        return not email or EMAIL_RE.match(email)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/blog', Blog),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/signup', SignupPage)
    ], debug=True)
