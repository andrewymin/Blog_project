from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
# from dotenv import load_dotenv
import os

app = Flask(__name__)
# Commented out code below to use env variables on Heroku
# load_dotenv("C:/Users/krazy/Desktop/Code/Starting+Files+-+blog-with-users-start/.env")
# SECRET_KEY = os.getenv("secret_key")
SECRET_KEY = os.environ.get("secret_key")

app.config['SECRET_KEY'] = SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
# Below added 'DATABASE_URL' as an env variable for heroku, also added 'sqlite:///blog.db' for local functionality
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("POSTGRESQL_URL", 'sqlite:///blog.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##LOGIN REQUIRMENTS
login_manager = LoginManager()
login_manager.init_app(app)

##PROFILE PICTURE RANDOMIZER SETTINGS
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES
##CREATE TABLE IN DB
##Added UserMixin to class parameters to inherit providing default implementations for all of these properties and method
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(500))
    name = db.Column(db.String(100))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship("Comment", back_populates="user")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)

    #Create Foreign Key, "users.id" the users refers to the tablename of User.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")
    post_comments = relationship("Comment", back_populates="blog")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blog = relationship("BlogPost", back_populates="post_comments")


# if app.config['SQLALCHEMY_DATABASE_URI'] == os.environ.get("DATABASE_URL"):
#     db.create_all()
if not os.path.isfile('sqlite:///blog.db'):
    db.create_all()


##This callback is used to reload the user object from the user ID stored in the session.
# Make sure to use the right database for this method
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return wrapper


#########################################################################################


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_exist = User.query.filter_by(email=user_email).first()
        if user_exist:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            user_password = form.password.data
            # optionally add salt rounds with <salt_length=<any number>> in params of generate_password_hash(<password>)
            hash_pass = generate_password_hash(user_password)
            new_user = User(
                email=user_email,
                password=hash_pass,
                name=form.name.data,
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        login_email = form.email.data
        user_exists = User.query.filter_by(email=login_email).first()
        if user_exists:
            login_password = check_password_hash(user_exists.password, form.password.data)
            if login_password:
                login_user(user_exists)
                return redirect(url_for('get_all_posts'))
            flash("Incorrect Password, try again")
            return redirect(url_for("login"))
        flash("You don't seem to have a account with us. Sign up instead.")
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():

        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        comment = form.comment.data
        new_comment = Comment(
            # Must add the database relational variable with RELATIONSHIP method to get each id of each db
            comment=comment,
            # Using Current_user to get the logged-in users id
            user=current_user,
            # Using the requested_post variable created above when querying for correct post to get that post id
            blog=requested_post,
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route('/delete/<int:comment_id>/<int:post_id>', methods=['GET', 'POST'])
# @login_required
def delete_comment(comment_id, post_id):
    comment_to_delete = Comment.query.get(comment_id)
    post_to_return = post_id
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_to_return))


if __name__ == "__main__":
    app.run(debug=True)
