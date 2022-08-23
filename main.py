from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from flask import abort
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from sqlalchemy import Table, Column, Integer, ForeignKey
import os
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author = db.relationship('User', back_populates="posts")
    comments = db.relationship('Comment', back_populates = "parent_post")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = db.relationship('BlogPost', back_populates="author")
    comments = db.relationship('Comment', back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, ForeignKey('users.id'))
    author = db.relationship('User', back_populates = "comments")
    post_id = db.Column(db.Integer, ForeignKey('blog_posts.id'))
    parent_post = db.relationship('BlogPost', back_populates = "comments")

print("before create all")
db.create_all()
print("after create all")

login_manager = LoginManager()
login_manager.init_app(app)


def admin_only(f):
    @wraps(f)
    def wrapper_func(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        else:
            return f(*args, **kwargs)
    return wrapper_func


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def get_user_id():
    user_id = 0
    if current_user.is_authenticated:
        user_id = int(current_user.get_id())
        print(user_id, type(user_id))
    return user_id


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    user_id = get_user_id()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated,
                           user_id=user_id)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    user = User.query.filter_by(email=form.email.data).first()
    if user:
        flash("This email is already registered, login instead.")
        return redirect(url_for('login'))

    if form.validate_on_submit():
        new_user = User(
            email = form.email.data,
            password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8),
            name = form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash("Password is incorrect, please try again.")
                return redirect(url_for('login'))
        else:
            flash("This email is not registered, please register.")
            return redirect(url_for('login'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments_on_post = Comment.query.filter_by(post_id=post_id).all()
    user_id = get_user_id()
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.comment.data,
            author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("post.html", post=requested_post,
                           form=form,
                           comments=comments_on_post,
                           logged_in=current_user.is_authenticated,
                           user_id=user_id)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


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
    user_id = get_user_id()
    return render_template("make-post.html", form=form,
                           logged_in = current_user.is_authenticated,
                           is_edit=current_user.is_authenticated,
                           user_id=user_id)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    user_id = get_user_id()
    return render_template("make-post.html", form=edit_form,
                           logged_in=current_user.is_authenticated,
                           is_edit=current_user.is_authenticated,
                           user_id=get_user_id())


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
