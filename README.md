# Front-End Portfolio

## About
This website is a portfolio of front-end projects created while following Udacity's Front-End Developer Nanodegree program.  This currently only consists of the portfolio page and the blog application.

## To Run
To run locally, run the following from the project folder:
```
dev_appserver.py app.yaml
```

Or go to the deployed app at:

<https://blog-161405.appspot.com>

## Project Specifications

### Multi-User Blog

#### About
This is a multi-user blog application that allows the creation of new users, and allows them to create, comment on, edit, and delete blog posts.  It also allows for voting on blog posts and comments.

The front page displays the ten newest blog posts along with author/date/voting score information on the blogs.  Clicking on the title of any blog post will take you to that blog post's page, where the user can view and create comments about that post.

#### Known Issues/Fixes to Come
* There is currently no way to query all past blog posts.  If you do not know the link for a particular post and it is not among the 10 newest posts, there is no way to find it from the website.

* Deleting posts does not delete the comments associated with that post.  If the ability to look at your own past comments is added in the future, these comments should still exist with no post parent, but for now they become inaccessible without a post page to view them on.

* Since the blog posts allow for HTML styling, the blog post entry box is vulnerable.  I am looking for a markdown library to include that allows markdown user input, but the Google App Engine is very strict about the libraries that can be included.

* Local caching was implemented because this application is running on Google App Engine's DB library, which does not have the mem_cache available like the NDB library does.  Because writes to the database are much slower than reads, this can cause some of the following issues:
    - Upvoting a post on the main page writes the new score value and refreshes the page.  When the page reads the score value for that post, it has not completed the write yet, so it will appear as if no upvote happened until another refresh occurs.    
    - Upvoting comments has the same issues
    - Deleting comments on a post's page will attempt to delete and refresh the page.  The deleted comment will still appear because the delete operation hasn't completed.
    - When creating a new comment, it seems to take a longer time to add that comment to the User's comment collection, and so upon refreshing the page, the Author of the comment does not appear.

    This is fixed with cookies being used for caching.  The user will see the results immediately, although other users will still get the slight delay if they attempted to refresh at that moment.

* If the username cookie is set before the password cookie in the SignIn handler, the username cookie is not stored.  Also, in the LogOut handler, if the clear_cookie call for username is before the clear_cookie call for password, username does not get cleared.  This requires further investigation, but for now, switching the order fixes the problem.
