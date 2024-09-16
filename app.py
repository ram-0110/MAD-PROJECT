from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    send_file,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import matplotlib.pyplot as plt
import io
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas



# -------------------------------  App  -----------------------------------------------

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "False"
db = SQLAlchemy(app)


# -------------------------------  Database  -----------------------------------------------


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(
        db.Enum("admin", "sponsor", "influencer", name="user_roles"), nullable=False
    )


class Sponsor(db.Model):
    __tablename__ = "sponsors"
    id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    user = db.relationship("User", backref=db.backref("sponsor", uselist=False))
    industry = db.Column(db.String(100), nullable=False)


class Influencer(db.Model):
    __tablename__ = "influencers"
    id = db.Column(db.Integer, db.ForeignKey("users.id"), primary_key=True)
    user = db.relationship("User", backref=db.backref("influencer", uselist=False))
    instagram_reach = db.Column(db.Integer, nullable=False)
    youtube_reach = db.Column(db.Integer, nullable=False)
    wallet = db.Column(db.Integer, default=0, nullable=False)
    niche = db.Column(db.String(100), nullable=False)



class Campaign(db.Model):
    __tablename__ = "campaigns"
    id = db.Column(db.Integer, primary_key=True)
    sponsor_id = db.Column(db.Integer, db.ForeignKey("sponsors.id"), nullable=False)
    sponsor = db.relationship("Sponsor", backref=db.backref("campaigns", lazy=True))
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    budget = db.Column(db.Float, nullable=False)
    


class AdRequest(db.Model):
    __tablename__ = "ad_requests"
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"), nullable=False)
    status = db.Column(
        db.Enum("Pending", "Accepted", "Rejected", name="request_status"),
        nullable=False,
        default="Pending",
    )
    request_creator = db.Column(
        db.Enum("Influencer", "Sponsor", name="request_creator"), nullable=False
    )
    sender_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    payment_amount = db.Column(db.Float, nullable=True)
    messages = db.Column(db.Text, nullable=True)
    requirements = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False, default=db.func.current_timestamp()
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )

    campaign = db.relationship("Campaign", backref=db.backref("ad_requests", lazy=True))
    sender = db.relationship(
        "User",
        foreign_keys=[sender_id],
        backref=db.backref("sent_ad_requests", lazy=True),
    )
    receiver = db.relationship(
        "User",
        foreign_keys=[receiver_id],
        backref=db.backref("received_ad_requests", lazy=True),
    )


class Flag(db.Model):
    __tablename__ = "flags"
    id = db.Column(db.Integer, primary_key=True)
    flagged_obj_type = db.Column(
        db.Enum("User", "Campaign", name="flagged_obj_type"), nullable=False
    )
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey("campaigns.id"), nullable=True)
    reason = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship(
        "User", foreign_keys=[user_id], backref=db.backref("flags", lazy=True)
    )
    campaign = db.relationship(
        "Campaign", foreign_keys=[campaign_id], backref=db.backref("flags", lazy=True)
    )


with app.app_context():
    db.create_all()
# -----------------------------   functions   -----------------------------------------------------

# -----------------------------   Routes   -----------------------------------------------------


@app.route("/signup/influencer")
def signup_influencer():
    return render_template("signup-influencer.html")


@app.route("/signup/sponsor")
def signup_sponsor():
    return render_template("signup-sponsor.html")


# --------------------------------------------------------------------------------


@app.route("/signup/influencer", methods=["POST"])
def signup_influencer_post():
    email = request.form.get("email")
    username = request.form.get("username")
    password1 = request.form.get("password1")
    password2 = request.form.get("password2")
    role = "influencer"
    youtube_reach = request.form.get("youtube_reach")
    instagram_reach = request.form.get("instagram_reach")
    niche = request.form.get("niche")


    if not username or not email or not password1 or not password2:
        flash("Please enter your details")
        return redirect(url_for("signup_influencer"))

    if password1 != password2:
        flash("Passwords do not match")
        return redirect(url_for("signup_influencer"))

    user = User.query.filter_by(username=username).first()

    if user:
        flash("Username already exists")
        return redirect(url_for("signup_influencer"))

    password_hash = generate_password_hash(password1)

    new_user = User(email=email, username=username, password=password_hash, role=role)
    db.session.add(new_user)
    db.session.commit()

    influencer = Influencer(
        id=new_user.id,
        instagram_reach=instagram_reach,
        youtube_reach=youtube_reach,
        wallet=0,
        niche=niche,
    )
    db.session.add(influencer)
    db.session.commit()

    return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/signup/sponsor", methods=["POST"])
def signup_sponsor_post():
    email = request.form.get("email")
    username = request.form.get("username")
    password1 = request.form.get("password1")
    password2 = request.form.get("password2")
    role = "sponsor"
    industry = request.form.get("industry")

    if not username or not email or not password1 or not password2:
        flash("Please enter your details")
        return redirect(url_for("signup_sponsor"))

    if password1 != password2:
        flash("Passwords do not match")
        return redirect(url_for("signup_sponsor"))

    user = User.query.filter_by(username=username).first()

    if user:
        flash("Username already exists")
        return redirect(url_for("signup_sponsor"))

    password_hash = generate_password_hash(password1)

    new_user = User(email=email, username=username, password=password_hash, role=role)
    db.session.add(new_user)
    db.session.commit()

    sponsor = Sponsor(id=new_user.id, industry=industry)
    db.session.add(sponsor)
    db.session.commit()

    return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/home/influencer/edit", methods=["POST"])
def edit_influencer_post():
    if "user" in session:
        user = User.query.get(session["user"])
        influencer = Influencer.query.get(user.id)
        flag = Flag.query.filter_by(user_id=user.id).first()
        if flag:
            flash("You cant edit profile as you are flagged")
            return redirect(url_for("home_influencer"))
        else:
            email = request.form.get("email")
            username = request.form.get("username")
            instagram_reach = request.form.get("instagram_reach")
            youtube_reach = request.form.get("youtube_reach")
            oldpassword = request.form.get("oldpassword")
            newpassword = request.form.get("newpassword")
            conformnewpassword = request.form.get("conformnewpassword")

            if instagram_reach:
                influencer.instagram_reach = instagram_reach
            if youtube_reach:
                influencer.youtube_reach = youtube_reach
            if email:
                user.email = email
            if username:
                user.username = username

            if oldpassword and newpassword and conformnewpassword:
                if not check_password_hash(user.password, oldpassword):
                    flash("Incorrect password")
                    return redirect(url_for("home_influencer"))
                if newpassword != conformnewpassword:
                    flash("Passwords do not match")
                    return redirect(url_for("home_influencer"))
                user.password = generate_password_hash(newpassword)
                db.session.commit()
                flash("Password updated successfully")
                return redirect(url_for("logout"))

            db.session.commit()

            flash("Profile updated successfully")
            return redirect(url_for("home_influencer"))
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/home/sponsor/edit", methods=["POST"])
def edit_sponsor_post():
    if "user" in session:
        user = User.query.get(session["user"])
        sponsor = Sponsor.query.get(user.id)
        flag = Flag.query.filter_by(user_id=user.id).first()
        if flag:
            flash("You cant edit profile as you are flagged")
            return redirect(url_for("home_sponsor"))
        else:
            email = request.form.get("email")
            username = request.form.get("username")
            oldpassword = request.form.get("oldpassword")
            newpassword = request.form.get("newpassword")
            conformnewpassword = request.form.get("conformnewpassword")

            if email:
                user.email = email
            if username:
                user.username = username
            if oldpassword and newpassword and conformnewpassword:
                if not check_password_hash(user.password, oldpassword):
                    flash("Incorrect password")
                    return redirect(url_for("home_sponsor"))
                if newpassword != conformnewpassword:
                    flash("Passwords do not match")
                    return redirect(url_for("home_sponsor"))
                user.password = generate_password_hash(newpassword)
                db.session.commit()
                flash("Password updated successfully")
                return redirect(url_for("logout"))

            db.session.commit()

            flash("Profile updated successfully")
            return redirect(url_for("home_sponsor"))
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/login")
def login():
    return render_template("login.html")


# --------------------------------------------------------------------------------


@app.route("/login", methods=["POST"])
def login_post():
    print("request recived")
    username = request.form.get("username")
    password = request.form.get("password")

    if not username or not password:
        flash("Please fill out all fields")
        return redirect(url_for("login"))

    if username == "admin" and password == "admin":
        session["user"] = "admin"
        return redirect(url_for("admin"))

    user = User.query.filter_by(username=username).first()

    if not user:
        flash("Username does not exist")
        return redirect(url_for("login"))

    if not check_password_hash(user.password, password):
        flash("Incorrect password")
        return redirect(url_for("login"))

    session["user"] = user.id
    flash("Login successful")

    if user.role == "sponsor":
        return redirect(url_for("home_sponsor"))
    elif user.role == "influencer":
        return redirect(url_for("home_influencer"))


# --------------------------------------------------------------------------------


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out")
    return redirect("login")


# --------------------------------------------------------------------------------




@app.route("/")
def main():
    if "user" in session:
        user=User.query.get(session["user"])
        return render_template("main.html",user=user)
    else:
        return render_template("main.html")


# --------------------------------------------------------------------------------




@app.route("/user/campaign/addcampaign", methods=["POST"])
def addcampaign_post():
    if "user" in session:

        user = User.query.get(session["user"])

        flag = Flag.query.filter_by(user_id=user.id).first()
        if flag:
            flash("You cant add campaign as you are flagged")
            return redirect(url_for("find_sponsor"))

        else:
            name = request.form.get("title")
            description = request.form.get("Description")
            start_date_str = request.form.get("start_date")
            end_date_str = request.form.get("end_date")
            budget = request.form.get("budget")

            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()

            if (
                not name
                or not description
                or not start_date
                or not end_date
                or not budget
            ):
                flash("Please enter all details")
                return redirect(url_for("addcampaign"))

            new_campaign = Campaign(
                sponsor_id=user.id,
                name=name,
                description=description,
                start_date=start_date,
                end_date=end_date,
                budget=budget,
            )
            db.session.add(new_campaign)
            db.session.commit()

            flash("Campaign added successfully")
            return redirect(url_for("find_sponsor"))
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


# --------------------------------------------------------------------------------


@app.route("/find/sponsor/edit/<int:id>", methods=["POST"])
def edit_campaign_post(id):
    if "user" in session:
        user = User.query.get(session["user"])
        campaign = Campaign.query.get(id)
        flag = Flag.query.filter_by(campaign_id=id).first()
        if flag:
            flash("You cant edit campaign as it is flagged")
            return redirect(url_for("find_sponsor"))
        else:
            name = request.form.get("name")
            description = request.form.get("description")
            start_date_str = request.form.get("start_date")
            end_date_str = request.form.get("end_date")
            budget = request.form.get("budget")

            if name:
                campaign.name = name
            if description:
                campaign.description = description
            if start_date_str != "":
                start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
                campaign.start_date = start_date
            if end_date_str != "":
                end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
                campaign.end_date = end_date
            if budget:
                campaign.budget = budget

            db.session.commit()

            flash("Campaign updated successfully")
            return redirect(url_for("find_sponsor"))
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/user/campaign/<int:id>/delete")
def delete_campaign(id):
    if "user" in session:
        user = User.query.get(session["user"])
        campaign = Campaign.query.get(id)
        ad_requests = AdRequest.query.filter_by(campaign_id=id).all()
        flag = Flag.query.filter_by(campaign_id=id).first()
        if flag:
            flash("You cant delete campaign as it is flagged")
            return redirect(url_for("find_sponsor"))
        else:
            for request in ad_requests:
                db.session.delete(request)
                db.session.commit()

            db.session.delete(campaign)
            db.session.commit()
            flash("Campaign deleted successfully")
            return redirect(url_for("find_sponsor"))
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------
@app.route("/home/influencer")
def home_influencer():
    if "user" in session:
        user = User.query.get(session["user"])
        influencer = Influencer.query.get(user.id)
        influencer_flag = Flag.query.filter_by(user_id=user.id).first()
        flagged = False
        if influencer_flag:
            flagged = True
        ad_requests = (
            db.session.query(AdRequest)
            .filter(
                (AdRequest.sender_id == user.id) | (AdRequest.receiver_id == user.id)
            )
            .all()
        )
        return render_template(
            "home-influencer.html",
            user=user,
            influencer=influencer,
            ad_requests=ad_requests,
            flagged=flagged,
            influencer_flag=influencer_flag,
        )
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/home/sponsor")
def home_sponsor():
    if "user" in session:
        user = User.query.get(session["user"])
        sponsor_flag = Flag.query.filter_by(user_id=user.id).first()
        flagged = False
        if sponsor_flag:
            flagged = True
        sponsor = Sponsor.query.get(user.id)
        ad_requests = (
            db.session.query(AdRequest)
            .filter(
                (AdRequest.sender_id == user.id) | (AdRequest.receiver_id == user.id)
            )
            .all()
        )
        return render_template(
            "home-sponsor.html",
            user=user,
            sponsor=sponsor,
            ad_requests=ad_requests,
            flagged=flagged,
            sponsor_flag=sponsor_flag,
        )
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/find/influencer")
def find_influencer():
    if "user" in session:
        user = User.query.get(session["user"])
        ad_requests = AdRequest.query.filter_by(sender_id=user.id).all()

        excluded_ad_requests = db.session.query(AdRequest.campaign_id).filter(
            (AdRequest.request_creator == "Influencer")
            & (AdRequest.sender_id == user.id)
            | (AdRequest.request_creator == "Sponsor")
            & (AdRequest.receiver_id == user.id)
        )

        available_campaigns = Campaign.query.filter(
            ~Campaign.id.in_(excluded_ad_requests)
        ).all()
        influencer = Influencer.query.get(user.id)

        campaigns = Flag.query.filter_by(flagged_obj_type="Campaign").all()
        campaign_ids = [campaign.campaign_id for campaign in campaigns]

        return render_template(
            "find-influencer.html",
            campaigns=available_campaigns,
            user=user,
            influencer=influencer,
            ad_requests=ad_requests,
            campaign_ids=campaign_ids,
        )
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/find/sponsor", methods=["GET"])
def find_sponsor():
    if "user" in session:
        user = User.query.get(session["user"])
        search_query = request.args.get("search", "")

        # Basic query for all influencers
        influencers_query = Influencer.query

        if search_query:
            search_query = f"%{search_query}%"
            influencers_query = influencers_query.join(User).filter(
                (User.username.ilike(search_query))
                | (Influencer.niche.ilike(search_query))
                | (Influencer.instagram_reach.ilike(search_query))
                | (Influencer.youtube_reach.ilike(search_query))
            )

        influencers = influencers_query.all()
        flag_influencers = Flag.query.filter_by(flagged_obj_type="User").all()
        flag_influencer_ids = [
            flag_influencer.user_id for flag_influencer in flag_influencers
        ]
        flag_campains = Flag.query.filter_by(flagged_obj_type="Campaign").all()
        flag_campain_ids = [flag_campain.campaign_id for flag_campain in flag_campains]

        return render_template(
            "find-sponsors.html",
            user=user,
            campaigns=Campaign.query.filter_by(sponsor_id=user.id).all(),
            influencers=influencers,
            flag_influencer_ids=flag_influencer_ids,
            flag_campain_ids=flag_campain_ids,
        )
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/find/influencer/<int:influencerid>/<int:sponsorid>/<int:campaignid>", methods=["POST", "GET"],)
def influ_sponsor_req(influencerid, sponsorid, campaignid):

    if "user" in session:

        flag = Flag.query.filter_by(user_id=influencerid).first()
        if flag:
            flash("You cant send request as you are flagged")
            return redirect(url_for("find_influencer"))
        else:

            payment_amount = request.form.get("payment_amount")
            messages = request.form.get("messages")
            requirements = request.form.get("requirements")

            campaign=Campaign.query.get(campaignid)
            new_request = AdRequest(
                campaign_id=campaignid,
                status="Pending",
                request_creator="Influencer",
                sender_id=influencerid,
                receiver_id=sponsorid,
                payment_amount=payment_amount,
                messages=messages,
                requirements=requirements,
            )
            db.session.add(new_request)
            db.session.commit()
            flash("Request sent successfully")
            return redirect(url_for("find_influencer"))
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route(
    "/find/sponsor/<int:sponsorid>/<int:influencerid>/<int:campaignid>",
    methods=["POST", "GET"],
)
def sponsor_influ_req(sponsorid, influencerid, campaignid):
    if "user" in session:

        flag = Flag.query.filter_by(user_id=sponsorid).first()
        if flag:
            flash("You cant send request as you are flagged")
            return redirect(url_for("find_sponsor"))
        else:
            payment_amount = request.form.get("payment_amount")
            messages = request.form.get("messages")
            requirements = request.form.get("requirements")

            if not messages:
                flash("Please enter messages amount")
                return redirect(url_for("find_sponsor"))

            campaign = Campaign.query.get(campaignid)
            if not campaign:
                flash("Campaign not found.")
                return redirect(url_for("find_sponsor"))

            # Check if a similar request already exists
            existing_request = AdRequest.query.filter_by(
                campaign_id=campaignid,
                sender_id=sponsorid,
                receiver_id=influencerid,
            ).first()

            existing_request_inf = AdRequest.query.filter_by(
                campaign_id=campaignid,
                sender_id=influencerid,
                receiver_id=sponsorid,
            ).first()

            if existing_request_inf:
                flash("Influencer alredy sent a request please check.")
                return redirect(url_for("find_sponsor"))

            if existing_request:
                flash("A similar request already exists.")
                return redirect(url_for("find_sponsor"))

            spon_request = AdRequest(
                campaign_id=campaignid,
                status="Pending",
                request_creator="Sponsor",
                sender_id=sponsorid,
                receiver_id=influencerid,
                payment_amount=payment_amount,
                messages=messages,
                requirements=requirements,
            )
            db.session.add(spon_request)
            db.session.commit()
            flash("Request sent successfully")
            return redirect(url_for("find_sponsor"))

    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/request/accept/<int:requestid>")
def req_accept(requestid):

    adRequest = AdRequest.query.get(requestid)
    campaign= Campaign.query.get(adRequest.campaign_id)
    flag = Flag.query.filter_by(user_id=adRequest.receiver_id).first()
    if flag:
        flash("You are flagged and cannot accept requests")
        if adRequest.request_creator == "Influencer":
            return redirect(url_for("home_sponsor"))
        else:
            return redirect(url_for("home_influencer"))
    else:
        if campaign.budget < adRequest.payment_amount:
            flash("Budget is not enough to accept the request")
            if adRequest.request_creator == "Influencer":
                return redirect(url_for("home_sponsor"))
            else:
                return redirect(url_for("home_influencer"))
        else:
            adRequest.status = "Accepted"
            db.session.commit()

            if adRequest.request_creator == "Influencer":
                influencer = Influencer.query.get(adRequest.sender_id)
                if influencer.wallet == 0:
                    influencer.wallet = adRequest.payment_amount
                    campaign.budget -= adRequest.payment_amount
                else:
                    influencer.wallet += adRequest.payment_amount
                    campaign.budget -= adRequest.payment_amount
                    
                db.session.commit()
                flash("Request accepted successfully")
                return redirect(url_for("home_sponsor"))
            else:
                influencer = Influencer.query.get(adRequest.receiver_id)
                if influencer.wallet == 0:
                    influencer.wallet = adRequest.payment_amount
                    campaign.budget -= adRequest.payment_amount
                else:
                    influencer.wallet += adRequest.payment_amount
                    campaign.budget -= adRequest.payment_amount
                db.session.commit()
                flash("Request accepted successfully")
                return redirect(url_for("home_influencer"))


# --------------------------------------------------------------------------------


@app.route("/request/reject/<int:requestid>")
def req_reject(requestid):
    adRequest = AdRequest.query.get(requestid)
    flag = Flag.query.filter_by(user_id=adRequest.receiver_id).first()
    if flag:
        flash("You are flagged you can't reject the request")
        if adRequest.request_creator == "Influencer":
            return redirect(url_for("home_sponsor"))
        else:
            return redirect(url_for("home_influencer"))
    else:
        adRequest.status = "Rejected"
        db.session.commit()

        if adRequest.request_creator == "Sponsor":
            return redirect(url_for("home_influencer"))
        else:
            return redirect(url_for("home_sponsor"))


# --------------------------------------------------------------------------------


@app.route("/admin")
def admin():
    if "user" in session:
        user = session["user"]

        if user != "admin":
            flash("You do not have permission to view this page")
            return redirect(url_for("main"))
        else:
            flags = Flag.query.all()
            return render_template("admin.html", user=user, flags=flags)
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/admin/find")
def admin_find():
    if "user" in session:
        user = session["user"]
        campaigns = Campaign.query.all()
        if user != "admin":
            flash("You do not have permission to view this page")
            return redirect(url_for("main"))
        else:
            return render_template("admin-find.html", user=user, campaigns=campaigns)
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/admin/flag/campain/<int:campainid>", methods=["POST", "GET"])
def admin_flag_campain(campainid):
    if "user" in session:
        user = session["user"]
        reason = request.form.get("reason")

        if user != "admin":
            flash("You do not have permission to view this page")
            return redirect(url_for("main"))
        else:
            if Flag.query.filter_by(campaign_id=campainid).first():
                flash("Campaign already flagged")
                return redirect(url_for("admin_find"))
            if not reason:
                flash("Please enter reason")
                return redirect(url_for("admin_find"))

            new_flag = Flag(
                flagged_obj_type="Campaign",
                campaign_id=campainid,
                reason=reason,
            )
            db.session.add(new_flag)
            db.session.commit()
            flash("Campaign flagged successfully")

            return redirect(url_for("admin_find"))

    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/admin/remove/flag/<int:flagid>")
def admin_remove_flag(flagid):
    if "user" in session:
        user = session["user"]

        if user != "admin":
            flash("You do not have permission to view this page")
            return redirect(url_for("main"))
        else:
            flag = Flag.query.get(flagid)
            db.session.delete(flag)
            db.session.commit()
            flash("Flag removed successfully")
            return redirect(url_for("admin"))
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/admin/flag/user/<int:userid>", methods=["POST", "GET"])
def admin_flag_user(userid):
    if "user" in session:
        user = session["user"]
        reason = request.form.get("reason")

        if user != "admin":
            flash("You do not have permission to view this page")
            return redirect(url_for("main"))
        else:
            if Flag.query.filter_by(user_id=userid).first():
                flash("User already flagged")
                return redirect(url_for("admin_find_user"))
            if not reason:
                flash("Please enter reason")
                return redirect(url_for("admin_find_user"))

            new_flag = Flag(
                flagged_obj_type="User",
                user_id=userid,
                reason=reason,
            )
            db.session.add(new_flag)
            db.session.commit()
            flash("User flagged successfully")
            return redirect(url_for("admin_find_user"))

    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/admin/find/users")
def admin_find_user():
    if "user" in session:
        user = session["user"]
        users = User.query.all()
        if user != "admin":
            flash("You do not have permission to view this page")
            return redirect(url_for("main"))
        else:
            return render_template("admin-find-user.html", user=user, users=users)
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/home/influencer/negociate/<int:requestid>", methods=["POST"])
def Negociate(requestid):
    if "user" in session:
        user = User.query.get(session["user"])
        adRequest = AdRequest.query.get(requestid)
        flag = Flag.query.filter_by(user_id=user.id).first()
        if flag:
            flash("You cant negociate as you are flagged")
            return redirect(url_for("home_influencer"))
        else:
            payment_amount = request.form.get("payment_amount")
            messages = request.form.get("messages")
            requirements = request.form.get("requirements")

            if not payment_amount:
                flash("Please enter payment amount")
                if adRequest.request_creator == "Influencer":
                    return redirect(url_for("home_influencer"))
                else:
                    return redirect(url_for("home_sponsor"))

            if messages:
                adRequest.messages = messages
            if requirements:
                adRequest.requirements = requirements

            adRequest.payment_amount = payment_amount
            adRequest.sender_id, adRequest.receiver_id = (
                adRequest.receiver_id,
                adRequest.sender_id,
            )

            if adRequest.request_creator == "Influencer":
                adRequest.request_creator = "Sponsor"
                db.session.commit()
                flash("Request sent successfully")
                return redirect(url_for("home_sponsor"))

            else:
                adRequest.request_creator = "Influencer"
                db.session.commit()
                flash("Request sent successfully")
                return redirect(url_for("home_influencer"))

    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


@app.route("/user_distribution")
def user_distribution():
    influencer_count = db.session.query(User).join(Influencer).count()
    sponsor_count = db.session.query(User).join(Sponsor).count()

    labels = [
        "Influencers",
        "Sponsors",
    ]
    sizes = [
        influencer_count,
        sponsor_count,
    ]
    colors = [
        "#ff9999",
        "#66b3ff",
    ]

    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
    ax.axis("equal") 

    canvas = FigureCanvas(fig)
    img = io.BytesIO()
    fig.savefig(img)
    img.seek(0)

    return send_file(img, mimetype="image/png")


# --------------------------------------------------------------------------------


@app.route("/sponsor_industry")
def spo_ind_stat():
    industry_counts = (
        db.session.query(Sponsor.industry, db.func.count(Sponsor.industry))
        .group_by(Sponsor.industry)
        .all()
    )

    industries = [industry for industry, count in industry_counts]
    counts = [count for industry, count in industry_counts]
    colors = [
        "#ff9999",
        "#66b3ff",
        "#99ff99",
        "#ffcc99",
        "#c2c2f0",
        "#ffb3e6",
    ]  

    fig, ax = plt.subplots()
    ax.bar(industries, counts, color=colors[: len(industries)])

    ax.set_title("Industries of Sponsors", fontsize=16)
    ax.set_xlabel("Industry", fontsize=14)
    ax.set_ylabel("Number of Sponsors", fontsize=14)
    plt.xticks(rotation=45, ha="right")

    canvas = FigureCanvas(fig)
    img = io.BytesIO()
    fig.savefig(img)
    img.seek(0)

    return send_file(img, mimetype="image/png")


# --------------------------------------------------------------------------------


@app.route("/influencer_neche")
def inf_spo_stat():
    industry_counts = (
        db.session.query(Influencer.niche, db.func.count(Influencer.niche))
        .group_by(Influencer.niche)
        .all()
    )

    industries = [industry for industry, count in industry_counts]
    counts = [count for industry, count in industry_counts]
    colors = [
        "#ff9999",
        "#66b3ff",
        "#99ff99",
        "#ffcc99",
        "#c2c2f0",
        "#ffb3e6",
    ]  

    fig, ax = plt.subplots()
    ax.bar(industries, counts, color=colors[: len(industries)])

    ax.set_title("Industries of Sponsors", fontsize=16)
    ax.set_xlabel("Industry", fontsize=14)
    ax.set_ylabel("Number of Sponsors", fontsize=14)
    plt.xticks(rotation=45, ha="right")

    canvas = FigureCanvas(fig)
    img = io.BytesIO()
    fig.savefig(img)
    img.seek(0)

    return send_file(img, mimetype="image/png")


# --------------------------------------------------------------------------------


@app.route("/flagged_user_camp")
def flg_usr_camp():
    flagged_users_count = (
        db.session.query(Flag).filter_by(flagged_obj_type="User").count()
    )
    flagged_campaigns_count = (
        db.session.query(Flag).filter_by(flagged_obj_type="Campaign").count()
    )

    labels = ["Flagged Users", "Flagged Campaigns"]
    counts = [flagged_users_count, flagged_campaigns_count]
    colors = ["#66b3ff", "#ff9999"]

    fig, ax = plt.subplots()
    ax.bar(labels, counts, color=colors)
    ax.set_title("Number of Flagged Users and Campaigns")
    ax.set_ylabel("Count")
    ax.set_xlabel("Flagged Object Type")

    canvas = FigureCanvas(fig)
    img = io.BytesIO()
    fig.savefig(img)
    img.seek(0)

    return send_file(img, mimetype="image/png")


# --------------------------------------------------------------------------------


@app.route("/ad_requests_admin_stats")
def ad_request_stats():

    accepted_count = db.session.query(AdRequest).filter_by(status="Accepted").count()
    pending_count = db.session.query(AdRequest).filter_by(status="Pending").count()

    labels = ["Accepted", "Pending"]
    sizes = [accepted_count, pending_count]
    colors = ["#4CAF50", "#FF9800"]  
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, colors=colors, autopct="%1.1f%%", startangle=90)
    ax.axis("equal")  


    canvas = FigureCanvas(fig)
    img = io.BytesIO()
    fig.savefig(img)
    img.seek(0)

    return send_file(img, mimetype="image/png")


# --------------------------------------------------------------------------------


@app.route("/stats")
def stats():
    if "user" in session:
        user = User.query.get(session["user"])
    #   ----------------------------------------------------------------

        niche_counts = (
            db.session.query(Influencer.niche, db.func.count(Influencer.niche))
            .group_by(Influencer.niche)
            .all()
        )
        niche = [industry for industry, count in niche_counts]
        niche_count = [count for industry, count in niche_counts]

        #   ----------------------------------------------------------------

        accepted_count = db.session.query(AdRequest).filter_by(status="Accepted").count()
        pending_count = db.session.query(AdRequest).filter_by(status="Pending").count()

        #   ----------------------------------------------------------------

        flagged_users_count = (
            db.session.query(Flag).filter_by(flagged_obj_type="User").count()
        )
        flagged_campaigns_count = (
            db.session.query(Flag).filter_by(flagged_obj_type="Campaign").count()
        )

        #   ----------------------------------------------------------------

        influencer_count = db.session.query(User).join(Influencer).count()
        sponsor_count = db.session.query(User).join(Sponsor).count()

        #   ----------------------------------------------------------------

        industry_counts = (
            db.session.query(Sponsor.industry, db.func.count(Sponsor.industry))
            .group_by(Sponsor.industry)
            .all()
        )
        industries = [industry for industry, count in industry_counts]
        ind_counts = [count for industry, count in industry_counts]

        #   ----------------------------------------------------------------

        return render_template(
            "stats.html",
            niche_counts=niche_counts,
            accepted_count=accepted_count,
            pending_count=pending_count,
            flagged_users_count=flagged_users_count,
            flagged_campaigns_count=flagged_campaigns_count,
            influencer_count=influencer_count,
            sponsor_count=sponsor_count,
            industry_counts=industry_counts,
            user=user
        )
    else:
        return redirect(url_for("login"))


# --------------------------------------------------------------------------------


if __name__ == "__main__":
    app.run(debug=True)


# --------------------------------------------------------------------------------
