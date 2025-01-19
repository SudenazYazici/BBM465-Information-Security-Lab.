from flask import Flask, render_template, request, flash, redirect, url_for
from Crypto.Hash import SHA256
from Server import Server

app = Flask(__name__)
app.secret_key = "secure_secret_key"
server = Server()


@app.route("/")
def index():
    """Redirect to the login page"""
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        val_password = request.form["val_password"]

        # Validate inputs
        if len(username) == 0 or not username.isalpha():
            flash("Invalid username: must be alphabetic.", "error")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("Password must be longer than 6 characters.", "error")
            return redirect(url_for("register"))
        if password != val_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        # Hash password and generate OTP chain
        hashed_password = SHA256.new(password.encode()).hexdigest()
        otp_chain = server.generate_otp_chain(password)

        # Register user
        success, message = server.register_user(username, hashed_password, otp_chain)
        flash(message, "success" if success else "error")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Hash the password
        hashed_password = SHA256.new(password.encode()).hexdigest()

        # Validate login credentials
        success, message = server.validate_login(username, hashed_password)
        if not success:
            flash(message, "error")
            return redirect(url_for("login"))

        # Generate OTP and validate it
        otp = server.get_next_otp(username)
        if otp:
            otp_success, otp_message = server.validate_otp(username, otp)
            if otp_success:
                flash("Login successful!", "success")
                return redirect(url_for("welcome", username=username))
            else:
                flash(otp_message, "error")
                return redirect(url_for("login"))
        else:
            flash("Unable to generate OTP.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/welcome")
def welcome():
    username = request.args.get("username", "Guest")
    return render_template("welcome.html", username=username)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
