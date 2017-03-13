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
        self.render('blog.html', posts = posts)

class NewPost(Handler):
    def get(self):
        self.render('newpost.html')

    def post(self):
        self.render('newpost.html')

# Database Tables
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    def render(self):
        self.__render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self)

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog', BlogPage),
                               ('/newpost', NewPost),
                               ],
                              debug=True)
