from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# Initialize the app, database, and login manager
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'  # SQLite database
app.config['SECRET_KEY'] = 'your_secret_key'  # Secret key for sessions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    posts = db.relationship('Post', backref='category', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    published = db.Column(db.Boolean, default=True)  # If the post is published
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)

# Flask-Login user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    posts = Post.query.filter_by(published=True).order_by(Post.date_posted.desc()).all()
    return render_template('home.html', posts=posts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Login failed. Check your username and/or password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', posts=posts)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category_name = request.form['category']
        category = Category.query.filter_by(name=category_name).first()
        if not category:
            category = Category(name=category_name)
            db.session.add(category)
            db.session.commit()

        # Create and add the post
        new_post = Post(title=title, content=content, user_id=current_user.id, category_id=category.id, published=True)
        db.session.add(new_post)
        db.session.commit()
        flash('New post added!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_post.html')

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash('You are not authorized to edit this post.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        post.category_id = Category.query.filter_by(name=request.form['category']).first().id
        db.session.commit()
        flash('Post updated!', 'success')
        return redirect(url_for('dashboard'))

    categories = Category.query.all()
    return render_template('edit_post.html', post=post, categories=categories)

@app.route('/delete_post/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash('You are not authorized to delete this post.', 'danger')
        return redirect(url_for('dashboard'))

    db.session.delete(post)
    db.session.commit()
    flash('Post deleted!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/unpublish_post/<int:post_id>')
@login_required
def unpublish_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash('You are not authorized to unpublish this post.', 'danger')
        return redirect(url_for('dashboard'))

    post.published = False
    db.session.commit()
    flash('Post unpublished!', 'success')
    return redirect(url_for('dashboard'))

# Add a default user if none exists
def add_user():
    with app.app_context():  # Ensuring the app context is active
        if not User.query.filter_by(username='admin').first():
            hashed_password = generate_password_hash('password123')
            new_user = User(username='admin', password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

if __name__ == "__main__":
    add_user()  # Add the admin user if it doesn't exist
    with app.app_context():
        db.create_all()  # Create all tables (run this once)
    app.run(debug=True)
