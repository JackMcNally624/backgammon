from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///backgammon_new.db')
app.config['SECURITY_PASSWORD_SALT'] = 'your-salt-here'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)  # Increased length for hash
    elo_rating = db.Column(db.Float, default=1500)
    games_played = db.Column(db.Integer, default=0)
    games_won = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    winner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    loser_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    winner_points = db.Column(db.Integer, nullable=False)
    loser_points = db.Column(db.Integer, nullable=True)  # Make it nullable
    
    # Add relationships with unique backref names
    winner = db.relationship('User', foreign_keys=[winner_id], backref=db.backref('won_games', lazy='dynamic'))
    loser = db.relationship('User', foreign_keys=[loser_id], backref=db.backref('lost_games', lazy='dynamic'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_elo_change(winner_rating, loser_rating, k=32):
    expected_winner = 1 / (1 + 10 ** ((loser_rating - winner_rating) / 400))
    rating_change = k * (1 - expected_winner)
    return rating_change

@app.route('/')
def index():
    top_players = User.query.order_by(User.elo_rating.desc()).limit(10).all()
    recent_games = Game.query.order_by(Game.date.desc()).limit(5).all()
    return render_template('index.html', top_players=top_players, recent_games=recent_games, User=User)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/log_game', methods=['GET', 'POST'])
@login_required
def log_game():
    if request.method == 'POST':
        opponent_username = request.form.get('opponent')
        winner = request.form.get('winner')
        winner_points = int(request.form.get('winner_points'))
        
        opponent = User.query.filter_by(username=opponent_username).first()
        if not opponent:
            flash('Opponent not found')
            return redirect(url_for('log_game'))
        
        winner_id = current_user.id if winner == 'me' else opponent.id
        loser_id = opponent.id if winner == 'me' else current_user.id
        
        winner_user = User.query.get(winner_id)
        loser_user = User.query.get(loser_id)
        
        # Calculate and update Elo ratings
        elo_change = calculate_elo_change(winner_user.elo_rating, loser_user.elo_rating)
        winner_user.elo_rating += elo_change
        loser_user.elo_rating -= elo_change
        
        # Update game statistics
        winner_user.games_played += 1
        winner_user.games_won += 1
        loser_user.games_played += 1
        
        # Log the game
        game = Game(
            winner_id=winner_id,
            loser_id=loser_id,
            winner_points=winner_points
        )
        
        db.session.add(game)
        db.session.commit()
        flash('Game logged successfully')
        return redirect(url_for('index'))
    
    users = User.query.filter(User.id != current_user.id).all()
    return render_template('log_game.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001) 