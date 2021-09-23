from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, ConfirmEmail
from flask_gravatar import Gravatar
from functools import wraps
from flask_script import Manager
from itsdangerous import URLSafeTimedSerializer
import datetime
import smtplib
import random
import os


# Handling email conformation
g_my_email = os.environ.get('MAIL_USERNAME')
g_password = os.environ.get('MAIL_PASSWORD')


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL",  "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('PASSWORD_SALT')
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


# Conformation of an EMAIL
# Generating confirm token
def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


def send_email(to, subject, conf_url):
    with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(user=g_my_email, password=g_password)
        connection.sendmail(from_addr=g_my_email, to_addrs=to,
                            msg=f'Subject:{subject}!'
                                f'\n\n{conf_url}')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.email != "sanamyi7@gmail.com" and current_user.email != "tohaartuhov@mail.ru":
            if current_user.admin == False:
                return abort(403)
        return f(*args, **kwargs)
    return decorated_function


# CONFIGURE TABLES
# Updated USER!
class User(UserMixin, db.Model):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    name = db.Column(db.String(100))
    registered_on = db.Column(db.DateTime, nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    blog_posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

    def __init__(self, email, password, confirmed, name,
                 paid=False, admin=False, confirmed_on=None):
        self.email = email
        self.password = password
        self.registered_on = datetime.datetime.now()
        self.admin = admin
        self.confirmed = confirmed
        self.confirmed_on = confirmed_on
        self.name = name


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = db.relationship("User", back_populates="blog_posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="comment_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment_post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    comment_post = db.relationship("BlogPost", back_populates="comments")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = db.relationship("User", back_populates="comments")
    text = db.Column(db.Text, nullable=False)

# db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, admins=admins)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if User.query.filter_by(email=register_form.email.data).first():
            flash("Account with this email already exist.")
            return redirect(url_for('register'))
        new_user = User(
            email=register_form.email.data,
            password=generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8),
            name=register_form.name.data,
            confirmed=False
        )
        db.session.add(new_user)
        db.session.commit()

        token = generate_confirmation_token(new_user.email)
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        subject = "Please confirm your email"
        send_email(new_user.email, subject, confirm_url)

        login_user(new_user)

        flash('A confirmation email has been sent via email.', 'success')
        return redirect(url_for("unconfirmed"))
    return render_template("register.html", form=register_form)


@app.route('/confirm/<token>')
@login_required
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('get_all_posts'))


@app.route('/resend')
@login_required
def resend_confirmation():
    token = generate_confirmation_token(current_user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(current_user.email, subject, html)
    flash('A new confirmation email has been sent.', 'success')
    return redirect(url_for('unconfirmed'))


@app.route('/unconfirmed')
@login_required
def unconfirmed():
    if current_user.confirmed:
        return redirect('get_all_posts')
    flash('Please confirm your account!', 'warning')
    return render_template('unconfirmed.html')


@app.route('/login', methods=["GET", "POST"])
def login():
    register_form = LoginForm()
    if register_form.validate_on_submit():
        user_email = register_form.email.data
        user_password = register_form.password.data

        user_data = User.query.filter_by(email=user_email).first()
        if user_data:
            user_hash = user_data.password

            if check_password_hash(pwhash=user_hash, password=user_password):
                login_user(user_data)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Wrong password.')
                return render_template('login.html', form=register_form)
        else:
            flash("This email doesn't exist in the database, please try again.")
            return render_template('login.html', form=register_form)
    return render_template('login.html', form=register_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments_posts = Comment.query.all()
    if form.validate_on_submit():
        if current_user.is_authenticated and current_user.confirmed:
            new_comment = Comment(
                text=form.comment.data,
                comment_author=current_user,
                comment_post=requested_post
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        elif current_user.is_authenticated:
            flash("Please, confirm your email to make a comment.")
            return redirect(url_for('unconfirmed'))
        else:
            flash("Please, log in to make a comment.")
            return redirect(url_for('login'))
    return render_template(
        "post.html", post=requested_post, form=form, current_user=current_user, comments=comments_posts)


# Users control
@app.route("/admin-only", methods=["GET", "POST"])
@admin_only
def admin_control():
    users = User.query.all()
    if request.method == "POST":
        new_user_name = request.form["new_name"]
        user_id = request.form["user_id"]
        user = User.query.get(user_id)
        user.name = new_user_name
        db.session.commit()
    return render_template("admin-only.html", users=users)


# delete user
@app.route("/delete/<int:user_id>")
@admin_only
def delete_user(user_id):
    user_to_delete = User.query.get(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('admin_control'))


@app.route("/about")
def about():
    return render_template("about.html")


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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete-comment/<int:post_id>/<int:comment_post_id>", methods=["GET", "POST"])
@login_required
def delete_comment(post_id, comment_post_id):
    comment_to_delete = Comment.query.get(comment_post_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/make-admin/<int:user_id>")
@admin_only
def make_admin(user_id):
    user = User.query.get(user_id)
    if user.admin == False:
        user.admin = True
    else:
        user.admin = False
    db.session.commit()
    return redirect(url_for('admin_control'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run()

