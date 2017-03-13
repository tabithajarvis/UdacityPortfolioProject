import os

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Page Handlers
class MainPage(Handler):
    def get(self):
        self.render('index.html')

class BlogPage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('blog.html', posts=posts)

class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        title = self.request.get('title')
        blogpost = self.request.get('blogpost')

        if title and blogpost:
            p = Post(parent=blog_key(), title=title, blogpost=blogpost)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Please enter a title and post content."
            self.render('newpost.html', title=title, blogpost=blogpost, error=error)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post,id=str(post.key().id()))

# Database Tables
def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    title = db.StringProperty(required=True)
    blogpost = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self.__render_text = self.blogpost.replace('\n', '<br>')
        return render_str("post.html", p=self, id=str(self.key().id()))

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog', BlogPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/([0-9]+)', PostPage),
                               ],
                              debug=True)
