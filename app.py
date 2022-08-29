import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute("SELECT * FROM stock_records WHERE userid= :id", id=session["user_id"])
    cash = db.execute("SELECT cash from users WHERE id= :id", id=session["user_id"])
    cash = cash[0]['cash']

    #to calculate current total value
    current_total = cash


    for stock in stocks:
        record = lookup(stock['symbol'])
        stock['name'] = record['name']
        stock['price'] = record['price']
        #calculate first before changing format

        stock['total'] = stock['price'] * stock['shares']
        current_total = current_total + stock['total']

        #change format
        stock['price'] = usd(stock['price'])
        stock['total'] = usd(stock['total'])

    return render_template("index.html", stocks=stocks, cash=usd(cash), current_total=usd(current_total))








@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        #check if there is such symbol
        quote = lookup(symbol)

        #symbol not provided or invalid symbol
        if quote == None:
            return apology("Invalid symbol or Please provide symbol")

        #shares not provided
        if shares == '':
            return apology("Missing Shares")

        if not shares.isdigit():
            return apology("You cannot buy fractional shares", 400)

        #calculate total price
        shares = int(shares)

        purchase = quote['price'] * shares

        #check user cash
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])[0]['cash']
        if (cash - purchase) < 0:
            return apology("you cannot afford the number of shares at current price")

        #check user already once buy that stock
        row = db.execute("SELECT * FROM stock_records WHERE userid = :id AND symbol = :symbol",
                         id=session["user_id"], symbol=symbol)

        #if user don't have that stock, insert into db
        if len(row) == 0:
            db.execute("INSERT INTO stock_records (userid, symbol, shares) VALUES (:id, :symbol, :shares)",
                       id=session["user_id"], symbol=symbol, shares=shares)
        else:
            prev_shares = db.execute("SELECT shares FROM stock_records WHERE userid = :id AND symbol = :symbol",
                               id=session["user_id"], symbol=symbol)
            prev_shares = prev_shares[0]["shares"]
            current_shares = prev_shares + shares
            #update the shares if already have
            db.execute("UPDATE stock_records SET shares = :current_shares WHERE userid = :id AND symbol = :symbol",
                   current_shares=current_shares, id=session["user_id"], symbol=symbol)

        #update cash after buy stocks
        new_cash = cash - purchase
        db.execute("UPDATE users SET cash = :new_cash WHERE id = :id", new_cash = new_cash , id=session["user_id"])

        #add into history
        db.execute("INSERT INTO history (userid, symbol, shares, price) VALUES (:userid, :symbol, :shares, :price)",
                   userid=session["user_id"], symbol=symbol, shares=shares, price=quote['price'])

        flash("Bought")

        return redirect("/")











@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    # return all rows from history
    stocks = db.execute("SELECT * FROM history WHERE userid = :userid", userid=session["user_id"])

    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("Invalid Symbol", 400)
        else:
            name = symbol['name']
            symbols = symbol['symbol']
            price = symbol['price']
            price = usd(price)
            return render_template("quoted.html", symbols = symbols, name = name, price = price)



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""


    if request.method == "POST":

        username = request.form.get("username")
        init_password = request.form.get("password")
        last_password = request.form.get("confirmation")

        if not username:
            return apology("Please provide a username")

        if not init_password:
            return apology("Please provide a password")

        if not last_password:
            return apology("Please comfirm your password ")

        if init_password != last_password:
            return apology("Your passwords do not match each other")
        else:
            password = init_password

        #hash password
        password_hash =  generate_password_hash(password, method = 'pbkdf2:sha256', salt_length = 8)

        #check if there is such username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=username)

        #if username already exist, invalid username
        if len(rows) != 0:
            return apology("username already exists", 400)



        #if passed all conditions above, create corresponding account
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)",
                   username=username, hash=password_hash)

        return redirect("/")





    else:
        return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":

        #return current user stocks
        symbols = db.execute("SELECT symbol from stock_records where userid= :id", id=session['user_id'])

        return render_template("sell.html", symbols = symbols)
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Missing symbol")
        shares = request.form.get("shares")

        if not shares:
            return apology("Missing shares")

        quote = lookup(symbol)
        stocks = db.execute("SELECT * FROM stock_records WHERE userid = :id AND symbol = :symbol",
                          id=session["user_id"], symbol=symbol)


        owned_shares = stocks[0]['shares']
        shares = int(shares)
        if shares > owned_shares:
            return apology("Too many shares")
        else:
            current_shares = owned_shares - shares

        #if shares still left
        if current_shares > 0:
            db.execute("UPDATE stock_records SET shares = :current_shares WHERE userid = :id AND symbol = :symbol",
                       current_shares=current_shares, id=session["user_id"], symbol=symbol)
        else:
            #No share left, delete record
            db.execute("DELETE FROM stock_records WHERE symbol = :symbol AND userid = :id",
                       symbol=symbol, id=session["user_id"])


        #get cash of current user
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session['user_id'])
        cash = cash[0]['cash']
        sell_price = quote['price'] * shares

        #update cash after sold
        cash = cash + sell_price
        # update user's balance in users table
        db.execute("UPDATE users SET cash = :cash WHERE id = :id",
                   cash=cash, id=session["user_id"])

        # changed into minus because of sell
        shares = shares * (-1)
        #add into history
        db.execute("INSERT INTO history (userid, symbol, shares, price) VALUES (:userid, :symbol, :shares, :price)",
                   userid=session["user_id"], symbol=symbol, shares=shares, price=quote['price'])

        flash("Sold!")

        return redirect("/")


@app.route("/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("password.html")

    else:
        old = request.form.get("oldPassword")
        new = request.form.get("newPassword")
        confirm = request.form.get('confirmPassword')

        #check old password
        hash_pass = db.execute("SELECT hash FROM users WHERE id = :id", id=session["user_id"])
        hash_pass = hash_pass[0]['hash']

        if not check_password_hash(hash_pass, old):
            return apology("Incorrect old password", 403)

        #check new password match
        if new != confirm:
            return apology("New passwords dun match each other", 400)

        #hash new password

        hash = generate_password_hash(new)

        #update new password in users
        db.execute("UPDATE users SET hash = :hash WHERE id = :id", hash=hash, id=session["user_id"])

        flash("Your password has changed successfully!")

        return redirect("/")
