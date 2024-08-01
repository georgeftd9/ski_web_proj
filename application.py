import os
import binascii
import json
import secrets
import boto3
import logging
import requests
import stripe
import re
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, session
from flask_sslify import SSLify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from io import BytesIO
from flask import session, flash
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from flask_cors import CORS
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from functools import wraps
from urllib.parse import urlparse, urljoin
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask import abort
from werkzeug.middleware.proxy_fix import ProxyFix

# Hardcoded credentials for testing
application = Flask(__name__)
Talisman(application, content_security_policy=None)
csrf = CSRFProtect(application)
application.wsgi_app = ProxyFix(application.wsgi_app, x_proto=1, x_host=1)

aws_region = 'us-west-1'

aws_access_key_id = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
stripe.api_key = os.environ.get('STRIPE_API_KEY')
stripe_webhook_key = os.environ.get('STRIPE_WEBHOOK_KEY')

secret_key = os.urandom(24)
secret_key_hex = binascii.hexlify(secret_key).decode('utf-8')
# Create a session using your hardcoded credentials
session_boto = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key,
    region_name=aws_region
)

# Now you can use this session to create clients or resources
s3 = session_boto.client('s3')
IMAGE_BUCKET = 'snowcondition-image-bucket'
COMMENT_BUCKET = 'snowcondition-comments-bucket'
COUNTER_BUCKET = 'snowcondition-comments-counters-bucket'
BACKGROUND_IMAGE = "snowcondition-background-image-bucket"
AUTH_EMAIL_BUCKET = "snow-condition-auth-email"
CARPOOL_BUCKET = "snowcondition-carpool-posts"
USED_GEAR_BUCKET = "snowcondition-used-gear"
USED_GEAR_IMAGE_BUCKET = "snowcondition-used-gears-images"
INSTRUCTOR_POST_BUCKET = "snow-condition-instructor-posts"
INSTRUCTOR_POST_IMAGE_BUCKET = "snow-condition-instructor-post-images"
STRIPE_CUSTOMER_BUCKET = "snow-condition-stripe-customer-mapping"

application.config['SECRET_KEY'] = secret_key_hex
application.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
application.secret_key = secret_key
# application.config['SESSION_COOKIE_SECURE'] = False
application.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
application.config['SESSION_COOKIE_SECURE'] = True  # Ensure cookies are sent over HTTPS
application.config['REMEMBER_COOKIE_SECURE'] = True
application.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
application.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Control when cookies are sent
oauth = OAuth(application)

client_id = os.environ.get("AUTH_CLIENT_ID")
client_secret = os.environ.get("AUTH_CLIENT_SECRET")
api_base_url = os.environ.get("AUTH_API_BASE_URL")
access_token_url = os.environ.get("AUTH_ACCESS_TOKEN_URL")
authorize_url = os.environ.get("AUTH_AUTHORIZE_URL")
jwks_uri = os.environ.get("AUTH_JWKS_URI")
# promo = os.environ.get("PROMO_CODE")
promo = None

e_1 = os.environ.get("E_1")
e_3 = os.environ.get("E_3")
e_12 = os.environ.get("E_12")
p_1 = os.environ.get("P_1")
p_3 = os.environ.get("P_3")
p_12 = os.environ.get("P_12")

auth0 = oauth.register(
    'auth0',
    client_id=client_id,
    client_secret=client_secret,
    api_base_url=api_base_url,
    access_token_url=access_token_url,
    authorize_url=authorize_url,
    client_kwargs={
        'scope': 'openid profile email',
    },
    jwks_uri = jwks_uri
)

limiter = Limiter(app = application, key_func = get_remote_address)
snow_forecast_links = {
    'Cypress_Mountain': 'https://www.snow-forecast.com/resorts/Cypress-Mountain/6day/mid',
    'Grouse_Mountain': 'https://www.snow-forecast.com/resorts/Grouse-Mountain/6day/mid',
    'Whistler_Blackcomb': 'https://www.snow-forecast.com/resorts/Whistler-Blackcomb/6day/mid',
    'Mount_Seymour': 'https://www.snow-forecast.com/resorts/Mount-Seymour/6day/mid',
    'Blue_Mountain': 'https://www.snow-forecast.com/resorts/Blue-Mountain/6day/mid',
    'Snow_Valley': 'https://www.snow-forecast.com/resorts/Snow-Valley-Ski-Resort/6day/mid',
    'Mount_St_Louis': 'https://www.snow-forecast.com/resorts/Mt-St-Louis-Moonstone/6day/mid',
    'Hockley_Valley_Resort': 'https://www.snow-forecast.com/resorts/Hockley-Valley/6day/mid',
    'Horseshoe_Resort': 'https://www.snow-forecast.com/resorts/Horseshoe-Resort/6day/mid'
}

live_camera_links = {
    'Cypress_Mountain': 'https://cypressmountain.com/downhill-conditions-and-cams#webcams',
    'Grouse_Mountain': 'https://www.grousemountain.com/web-cams',
    'Whistler_Blackcomb': 'https://www.whistlerblackcomb.com/the-mountain/mountain-conditions/mountain-cams.aspx',
    'Mount_Seymour': 'https://mtseymour.ca/the-mountain/todays-conditions-hours',
    'Blue_Mountain': 'https://www.bluemountain.ca/mountain/webcams',
    'Snow_Valley': 'https://www.skisnowvalley.com/explore/webcams/',
    'Mount_St_Louis': 'https://www.mountstlouis.com/webcams/',
    'Hockley_Valley_Resort': 'https://www.youtube.com/watch?v=0C2wV6coE2c',
    'Horseshoe_Resort': 'https://horseshoeresort.com/webcams/'
}

logos = {
    'Cypress Mountain': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Cypress+Mountain.png',
    'Grouse Mountain': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Grouse+Mountain.png',
    'Whistler Blackcomb': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Whistler+Blackcomb.png',
    'Mount Seymour': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Mount+Seymour.png',
    'Blue Mountain': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Blue+Mountain.png',
    'Snow Valley': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Snow+Valley.png',
    'Mount St Louis': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Mount+St+Louis.png',
    'Hockley Valley Resort': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Hockley+Valley+Resort.png',
    'Horseshoe Resort': 'https://ski-resort-logs.s3.us-west-1.amazonaws.com/Horseshoe+Resort.png'
}

resort_name_replace_space = {
    'Cypress Mountain': 'Cypress_Mountain',
    'Grouse Mountain': 'Grouse_Mountain',
    'Whistler Blackcomb': 'Whistler_Blackcomb',
    'Mount Seymour': 'Mount_Seymour',
    'Blue Mountain': 'Blue_Mountain',
    'Snow Valley': 'Snow_Valley',
    'Mount St Louis': 'Mount_St_Louis',
    'Hockley Valley Resort': 'Hockley_Valley_Resort',
    'Horseshoe Resort': 'Horseshoe_Resort'
}

stripe_plan = {
    e_1 : 'Essential Plan',
    e_3 : 'Essential Plan',
    e_12 : 'Essential Plan',
    p_1 : 'Premium Plan',
    p_3 : 'Premium Plan',
    p_12 : 'Premium Plan'
}

type_to_plan = {
    "Premium Plan": {
        "1" : p_1,
        "3" : p_3,
        "12" : p_12,
    },
    "Essential Plan":{
        "1" : e_1,
        "3" : e_3,
        "12" : e_12,
    },
}

def generate_random_state():
    return secrets.token_urlsafe(16)  # Generates a 16-byte (128-bit) token

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in application.config['ALLOWED_EXTENSIONS']

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    # Enforce only HTTPS URLs are considered safe
    return test_url.scheme == 'https' and ref_url.netloc == test_url.netloc

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'profile' not in session:
            session['next'] = request.url  # Store the current URL before redirecting to login
            # Enforce HTTPS when redirecting to the login page
            login_url = url_for('login', _scheme='https', _external=True)
            return redirect(login_url)
        return f(*args, **kwargs)
    return decorated_function

# Auth0 login route
@application.route('/login')
def login():
    state = generate_random_state()
    session['auth_state'] = state

    # The redirect_uri can now be constructed without manually enforcing HTTPS
    redirect_uri = urljoin(request.url_root, 'callback')

    session['next'] = request.args.get('next') or request.referrer or None
    if session['next'] and not is_safe_url(session['next']):
        return abort(400, description="The redirect URL is not safe.")

    return auth0.authorize_redirect(redirect_uri=redirect_uri, _external=True, state=state)

# logging.basicConfig(level=logging.DEBUG)

@application.route('/callback')
def callback_handling():
    # Retrieve the state from the session and the response
    
    state_token = session.get('auth_state')
    state_from_auth0 = request.args.get('state', '')
    # Retrieve the authorization code and fetch the access token
    try:
        token = auth0.authorize_access_token()
        userinfo_response = auth0.get('userinfo', token=token)
        userinfo = userinfo_response.json()
    except Exception as e:
        logging.error(f"Error fetching user info: {e}")
        abort(500)
    session['auth0_user_id'] = userinfo['sub']
    auth0_user_id = session['auth0_user_id']
    if auth0_user_id:
        if has_stripe_id(auth0_user_id):
            stripe_customer_id = get_stripe_customer_id_from_auth0_user_id(auth0_user_id)
            if check_customer_has_subscription(stripe_customer_id):
                session['has_active'] = True

    key = 'auth_registered_email_list.json'
    try:
        response = s3.get_object(Bucket=AUTH_EMAIL_BUCKET, Key=key)
        emails = json.loads(response['Body'].read().decode())
        # ... existing code for updating emails ...
    except Exception as e:
        logging.error(f"Error interacting with S3: {e}")
        abort(500)
    if userinfo["sub"] not in emails.keys():
        emails[userinfo["sub"]] = userinfo["email"]
    else:
        print("email already in this list")
    s3.put_object(
        Body=json.dumps(emails),
        Bucket=AUTH_EMAIL_BUCKET,
        Key=key,
        ContentType='application/json'
    )
    
    session['profile'] = {
    'user_id': userinfo['sub'],
    'name': userinfo['name'],
    'picture': userinfo['picture']
    }
    session.permanent = True
    # Log the state values for debugging
    logging.debug(f"State from session: {state_token}")
    logging.debug(f"State from Auth0: {state_from_auth0}")

    # Validate the state
    if not state_token or state_token != state_from_auth0:
        logging.error("State validation failed")
        return 'State validation failed', 400

    base_url = request.url_root.rstrip('/')
    if not base_url.startswith('https://'):
        base_url = 'https://' + base_url.split('://')[1]
    redirect_uri = f'{base_url}/callback'

    # ... rest of your existing code ...

    # Redirect to the URL stored in session['next'] or to the home page
    next_url = session.pop('next', url_for('home', _scheme='https', _external=True))
    return redirect(next_url)
    

# Auth0 logout route
@application.route('/logout')
def logout():
    session.clear()
    # Enforce HTTPS for the returnTo URL
    return_to_url = url_for("home", _scheme='https', _external=True)
    params = {'returnTo': return_to_url, 'client_id': client_id}
    logout_url = f"{auth0.api_base_url}/v2/logout?{urlencode(params)}"
    return redirect(logout_url)

############################################

# Define the route for handling successful update of payment method
from flask import flash, redirect, request, session, url_for
import stripe

@application.route('/update_subscription_success')
def update_subscription_success():
    session_id = request.args.get('session_id')
    new_plan_id = request.args.get('new_plan_id')  # Retrieve the new_plan_id parameter
    if session_id:
        try:
            # Retrieve the Stripe session to confirm it's completed
            stripe_session = stripe.checkout.Session.retrieve(session_id)
            if stripe_session:
                # Retrieve the updated payment method
                # Now update the subscription with the new payment method
                subscriptions = stripe.Subscription.list(customer=stripe_session.customer, status='active')
                subscription_id = subscriptions.data[0].id
                updated_subscription = stripe.Subscription.modify(
                    subscription_id,
                    items=[{
                        'id': subscriptions.data[0]['items']['data'][0].id,
                        'plan': new_plan_id,
                    }],
                    proration_behavior='create_prorations',
                )
                invoice = stripe.Invoice.create(
                    customer=stripe_session.customer,
                    subscription=subscription_id,
                    auto_advance=True  # Automatically finalize the invoice
                )
                
                # Attempt to pay the invoice immediately
                stripe.Invoice.pay(invoice.id)
                # Confirm the subscription has been updated
                session['has_active'] = True
                flash('Subscription updated successfully.', 'success')
                return redirect(session.get('previous_url', url_for('home', _scheme='https', _external=True)))
            else:
                flash('Session not found.', 'error')
                return redirect(session.get('previous_url', url_for('home', _scheme='https', _external=True)))
        except Exception as e:
            flash(f"An error occurred: {e}", 'error')
            return redirect(session.get('previous_url', url_for('home', _scheme='https', _external=True)))
    # Redirect to the previous URL or home if not available
    return redirect(session.get('previous_url', url_for('home', _scheme='https', _external=True)))

@application.route('/update_subscription_cancelled')
def update_subscription_cancelled():
    # Provide feedback to the user
    flash('Payment information update was cancelled.', 'warning')
    # Redirect the customer to a page where they can attempt to update their payment method again or contact support
    return redirect(session.get('previous_url', url_for('home', _scheme='https', _external=True)))

@application.route('/subscribe')
@login_required
def subscribe():
    # Make sure to replace 'price_id' with your actual price ID from Stripe
    plan_type = request.args.get('plan')
    period = request.args.get('duration')
    session['previous_url'] = request.referrer or url_for('home', _scheme='https', _external=True)
    auth0_user_id = session.get('auth0_user_id')
    stripe_customer_id = get_stripe_customer_id_from_auth0_user_id(auth0_user_id)
    new_plan_id = type_to_plan[plan_type][period]
    print("!@#!@#!@#!@#!@#!@#!!#!#! our if")
    if stripe_customer_id and check_customer_has_subscription(stripe_customer_id):
        customer = stripe.Customer.retrieve(stripe_customer_id)
        current_subscription = stripe.Subscription.list(customer=stripe_customer_id, status='active')
        print(current_subscription['data'][0]['items']['data'][0]['id'], new_plan_id)
        print("!@#!@#!@#!@#!@#!@#!!#!#!")
        try:
            success_url = url_for('update_subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}&new_plan_id=' + new_plan_id
            cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
            print("after get url")
            checkout_session = stripe.checkout.Session.create(
                customer=stripe_customer_id,
                payment_method_types=['card'],
                mode='setup',
                success_url=success_url,
                cancel_url=cancel_url
            )
            # Redirect the customer to the Checkout page to update their payment method
            return redirect(checkout_session.url, code=303)
        except Exception as e:
            logging.error("Exception occurred", exc_info=True)
            flash(str(e), 'error')
            return redirect(url_for('home', _scheme='https', _external=True)) 
        # return redirect(modify_add_probation(stripe_customer_id, type_to_plan[plan_type][period]))
        
    old_customer = False
    if stripe_customer_id:
        old_customer = True
    else:
        old_customer = False
    print('plan id is: ', e_1)
    if not old_customer:
        if plan_type == "Essential Plan":
            if period == "1":
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer=get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': e_1,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        discounts=[{'promotion_code': promo}],
                        subscription_data={
                            'trial_period_days': 60  # Set this to the desired number of trial days
                        },
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    flash(f"An error occurred: {e}", 'error')
                    return redirect(url_for('home', _scheme='https', _external=True))      
            elif period == "3":
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': e_3,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        discounts=[{'promotion_code': promo}],
                        subscription_data={
                            'trial_period_days': 60  # Set this to the desired number of trial days
                        },
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))           
            else:
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': e_12,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        discounts=[{'promotion_code': promo}],
                        subscription_data={
                            'trial_period_days': 60  # Set this to the desired number of trial days
                        },
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))         

        if plan_type == "Premium Plan":
            if period == "1":
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': p_1,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        discounts=[{'promotion_code': promo}],
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))           
            elif period == "3":
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': p_3,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        discounts=[{'promotion_code': promo}],
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))         
            else:
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': p_12,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        discounts=[{'promotion_code': promo}],
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))
    # Existed Customer
    else:
        if plan_type == "Essential Plan":
            if period == "1":
                print("Enssetnail 1 month")
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': e_1,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))           
            elif period == "3":
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': e_3,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))          
            else:
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': e_12,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))          
        if plan_type == "Premium Plan":
            if period == "1":
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': p_1,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))           
            elif period == "3":
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': p_3,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))         
            else:
                try:
                    success_url = url_for('subscription_success', _scheme='https', _external=True) + '?session_id={CHECKOUT_SESSION_ID}'
                    cancel_url = url_for('subscription_cancelled', _scheme='https', _external=True)
                    checkout_session = stripe.checkout.Session.create(
                        customer =  get_stripe_customer_id_from_auth0_user_id(auth0_user_id),
                        success_url=success_url,
                        cancel_url=cancel_url,
                        payment_method_types=['card'],
                        mode='subscription',
                        line_items=[{
                            'price': p_12,  # Replace with the actual price ID
                            'quantity': 1,
                        }],
                        metadata = {'auth0_user_id': auth0_user_id},
                        #setup_future_usage='off_session',
                    )
                    return redirect(checkout_session.url, code=303)
                except Exception as e:
                    return redirect(url_for('home', _scheme='https', _external=True))

@application.route('/subscription-success')
def subscription_success():
    redirect_url = session.pop('previous_url', url_for('home', _scheme='https', _external=True))
    session['has_active'] = True
    return redirect(redirect_url)

@application.route('/subscription-cancelled')
def subscription_cancelled():
    redirect_url = session.pop('previous_url', url_for('home', _scheme='https', _external=True))
    return redirect(redirect_url)

@application.route('/stripe-webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    print("request head: ",request.headers)
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    print("sig header ---------------->")
    print( sig_header)
    logging.info(f"Received webhook with signature: {sig_header}")
    try:
        print("Enter try, before event")
        event = stripe.Webhook.construct_event(
            payload, sig_header, stripe_webhook_key
        ) # local webhook sc: whsec_01837639b2281acf6758b7547d7a684b90303580d1fd33c2a303ac7ffdffba11
        if event['type'] == 'invoice.payment_failed':
            stripe_session = event['data']['object']
            # Retrieve the subscription ID from the invoice object
            subscription_id = stripe_session.get('subscription')
            if subscription_id:
                # Delete the subscription immediately
                stripe.Subscription.delete(subscription_id)
                logging.info(f"Deleted subscription {subscription_id} due to payment failure.")
        # Handle the event
        elif event['type'] == 'checkout.session.completed':
            stripe_session = event['data']['object']
            # Here you can handle the checkout session completion, e.g., by updating your database
            handle_checkout_session(stripe_session)
            logging.info("Handled checkout.session.completed event")
        # ... handle other event types

    except ValueError as e:
        # Invalid payload
        logging.error(f"Invalid payload: {e}")
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        logging.error(f"Invalid signature: {e}")
        return 'Invalid signature', 400
    except Exception as e:
        logging.error(f"Error in webhook: {e}")
        return 'Internal Server Error', 500
    return 'Success', 200
#################################################
def check_customer_has_subscription(customer_id):
    subscriptions = stripe.Subscription.list(customer=customer_id)
    # print("?????????????????????? >>>>>>>>>>>, ", subscriptions)
    for subscription in subscriptions.auto_paging_iter():
        if subscription.status in ['active', 'canceled']:
            return True  # Customer has had a subscription before

        subscribe = subscriptions['data'][0]['items']['data'][0]['subscription']
        if subscription.trial_end > int(datetime.now().timestamp()):
            return True

def has_stripe_id(auth0_user_id):
    stripe_customer_id = get_stripe_customer_id_from_auth0_user_id(auth0_user_id)
    
    if stripe_customer_id:
        return True
    else:
        # No Stripe customer ID found for this Auth0 user ID
        return False

def get_stripe_customer_id_from_auth0_user_id(auth0_user_id):
    file_name = f"stripe_customer_mapping.json"
    try:
        response = s3.get_object(Bucket = STRIPE_CUSTOMER_BUCKET, Key = file_name)
        mapping = json.loads(response['Body'].read().decode())
        return mapping.get(auth0_user_id)
    except Exception as e:
        # File not found means no mappings have been saved yet
        return None

def save_stripe_customer_id_for_auth0_user_id(auth0_user_id, stripe_customer_id):
    print("Enter Save striper cusomter")
    file_name = "stripe_customer_mapping.json"
    try:
        # Load existing mappings
        try:
            response = s3.get_object(Bucket=STRIPE_CUSTOMER_BUCKET, Key=file_name)
            mapping = json.loads(response['Body'].read().decode())
            print("In save stripe, finish load current list")
        except Exception as e:
            print("In save stripe, No current load, create new mapping")
            mapping = {}

        # Update mapping with the new Stripe customer ID
        print("In save stripe, update mapping.   auth id: ",auth0_user_id, "         stripe id: ",stripe_customer_id)
        mapping[auth0_user_id] = stripe_customer_id

        # Save the updated mappings back to S3
        print("In save stripe, going to save on AWS S3, BUCKER: ", STRIPE_CUSTOMER_BUCKET, "   File name: ", file_name)
        s3.put_object(
            Body=json.dumps(mapping),
            Bucket=STRIPE_CUSTOMER_BUCKET,
            Key=file_name,
            ContentType='application/json'
        )
        print("In save stripe, finish save on AWS")
    except Exception as e:
        print(f"Error while saving mapping: {e}")

def handle_checkout_session(stripe_session):
    print("enter handle checkout")
    try:
        stripe_customer_id = stripe_session.get('customer')
        print("finish strip id ")
    except Exception as e:
        print(f'Error get stripe ID')
    try:
        auth0_user_id = stripe_session.get('metadata', {}).get('auth0_user_id')
        print("Finish try auth0 id")
    except Exception as e:
        logging.error("Enter exception for auth id")
        print(f"error get auth id")
    # Save the Stripe customer ID with the Auth0 user ID
    save_stripe_customer_id_for_auth0_user_id(auth0_user_id, stripe_customer_id)
################################################

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'profile' not in session:
            # Redirect to login page if the user is not logged in
            return redirect('/login', _scheme='https', _external=True)
        return f(*args, **kwargs)
    return decorated_function

# Use the decorator to protect routes
@application.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', userinfo=session['profile'])

@application.route('/logo')
def home_logo():
    key = "logo.png"
    file_obj = s3.get_object(Bucket = BACKGROUND_IMAGE, Key = key)
    return send_file(BytesIO(file_obj['Body'].read()), mimetype='image/jpeg')

@application.route('/background-image')
def background_image():
    key = 'ski_background_3.png'
    file_obj = s3.get_object(Bucket = BACKGROUND_IMAGE, Key = key)
    return send_file(BytesIO(file_obj['Body'].read()), mimetype='image/jpeg')

@application.route('/card-background-image')
def card_background_image():
    key = 'powder.jpg'
    file_obj = s3.get_object(Bucket = BACKGROUND_IMAGE, Key = key)
    return send_file(BytesIO(file_obj['Body'].read()), mimetype='image/jpeg')

@application.route('/cancel_plan/<sub_id>')
def cancel_plan(sub_id):
    try:
        subscription = stripe.Subscription.retrieve(sub_id)
        if subscription.trial_end > int(datetime.now().timestamp()):
            subscription.delete()
            return redirect(url_for('subscription', _scheme='https', _external=True))
    except stripe.error.StripeError as e:
    # Handle Stripe-specific errors here
        print(f"Stripe error occurred: {e}")
    except Exception as e:
        # Handle other unforeseen errors
        print(f"An unexpected error occurred: {e}")
    try:
        stripe.Subscription.modify(
            sub_id,
            cancel_at_period_end=True,
        )
        print(">>>>>>>>>>>>>>>>>>>>>>",stripe.Subscription.retrieve(sub_id).cancel_at_period_end)
        return redirect(url_for('subscription', _scheme='https', _external=True))
    except stripe.error.StripeError as e:
    # Handle Stripe-specific errors here
        print(f"Stripe error occurred: {e}")

def comment_option_lst():
    key = "snow_forecast_lift.json"
    response = s3.get_object(Bucket = BACKGROUND_IMAGE, Key = key)
    comment_option_lst = json.loads(response['Body'].read().decode())
    return comment_option_lst

def carpool_option_lst():
    key = "carpool_option.json"
    response = s3.get_object(Bucket = BACKGROUND_IMAGE, Key = key)
    carpool_option = json.loads(response['Body'].read().decode())
    return carpool_option

def used_gear_option_lst():
    key = "used_gear.json"
    response = s3.get_object(Bucket = BACKGROUND_IMAGE, Key = key)
    used_gear_option = json.loads(response['Body'].read().decode())
    return used_gear_option

def instruct_post_options_lst():
    key = "instructor_option.json"
    response = s3.get_object(Bucket = BACKGROUND_IMAGE, Key = key)
    instructor_option = json.loads(response['Body'].read().decode())
    return instructor_option

@application.route('/')
def home():
    is_sub = False
    if 'auth0_user_id' in session:
        print(">>>>>>>>>>>>>>>>>>>>>>>>>>>",session['auth0_user_id'])
        auth0_user_id = session['auth0_user_id']
        if auth0_user_id:
            if has_stripe_id(auth0_user_id):
                stripe_customer_id = get_stripe_customer_id_from_auth0_user_id(auth0_user_id)
                if check_customer_has_subscription(stripe_customer_id):
                    is_sub = True
    auth_is_logged_in = 'profile' in session
    current_status = read_all_resort()
    return render_template("home.html",logos = logos, resort_name_replace_space = resort_name_replace_space, is_logged_in = is_sub, auth_is_logged_in = auth_is_logged_in, current_status = current_status, area_mountain = area_mountain_ref)

@application.route('/subscription')
def subscription():
    if 'profile' not in session:
        return redirect(url_for('home', _scheme='https', _external=True))

    auth0_user_id = session['auth0_user_id']
    stripe_customer_id = get_stripe_customer_id_from_auth0_user_id(auth0_user_id)
    print("Strupe id: ", stripe_customer_id)
    essential_plan = False
    premium_plan =False

    user_info = {}

    if stripe_customer_id:
        subscribe_lst = stripe.Subscription.list(customer=stripe_customer_id, status='active')
        # print("Data is ",subscribe_lst["data"])
        if not subscribe_lst["data"]:
            print("enter")
            sub_test = stripe.Subscription.list(customer=stripe_customer_id)
            print(sub_test)
            for i in sub_test:
                subscribe = i['items']['data'][0]['subscription']
                current_sub = stripe.Subscription.retrieve(subscribe)
                current_stripe_plan_id = i['items']['data'][0]['price']['id']
                interval_count = i['items']['data'][0]['price']['recurring']['interval_count']
                interval = i['items']['data'][0]['price']['recurring']['interval']
                if interval == "year":
                    interval_count = 12
                time_expire = i['current_period_end']
                subscribe = i['items']['data'][0]['subscription']
                time_expire = datetime.utcfromtimestamp(time_expire)
                now_utc = datetime.utcnow()
                delta = time_expire - now_utc
                months_difference = delta.days / 30 + (delta.seconds / (30 * 24 * 3600)) - 0.03
                time_expire = time_expire.strftime('%Y-%m-%d')
                user_info['remaining_month'] = months_difference
                user_info['plan'] = stripe_plan[current_stripe_plan_id]
                user_info['plan_expire'] = time_expire
                user_info['interval'] = interval_count
                user_info['status'] = 'trial'
                user_info['sub'] = subscribe
                
                print(">>>>>>>>>>>> trail & active", user_info)
                return render_template('subscription.html', user_info=user_info)

        for i in subscribe_lst:
            subscribe = i['items']['data'][0]['subscription']
            current_sub = stripe.Subscription.retrieve(subscribe)
            if current_sub.status == "active" and current_sub.cancel_at_period_end:
                current_stripe_plan_id = i['items']['data'][0]['price']['id']
                interval_count = i['items']['data'][0]['price']['recurring']['interval_count']
                interval = i['items']['data'][0]['price']['recurring']['interval']
                if interval == "year":
                    interval_count = 12
                time_expire = i['current_period_end']
                subscribe = i['items']['data'][0]['subscription']
                time_expire = datetime.utcfromtimestamp(time_expire)
                now_utc = datetime.utcnow()
                delta = time_expire - now_utc
                months_difference = delta.days / 30 + (delta.seconds / (30 * 24 * 3600)) - 0.03
                time_expire = time_expire.strftime('%Y-%m-%d')
                user_info['remaining_month'] = months_difference
                user_info['plan'] = stripe_plan[current_stripe_plan_id]
                user_info['plan_expire'] = time_expire
                user_info['interval'] = interval_count
                user_info['status'] = 'canceled'
                user_info['sub'] = subscribe
                
                print(">>>>>>>>>>>> cancel & active")
                return render_template('subscription.html', user_info=user_info)

            elif current_sub.status == "active":
                current_stripe_plan_id = i['items']['data'][0]['price']['id']
                interval_count = i['items']['data'][0]['price']['recurring']['interval_count']
                interval = i['items']['data'][0]['price']['recurring']['interval']
                if interval == "year":
                    interval_count = 12
                time_expire = i['current_period_end']
                subscribe = i['items']['data'][0]['subscription']
                time_expire = datetime.utcfromtimestamp(time_expire)
                now_utc = datetime.utcnow()
                delta = time_expire - now_utc
                months_difference = delta.days / 30 + (delta.seconds / (30 * 24 * 3600)) - 0.03
                time_expire = time_expire.strftime('%Y-%m-%d')
                user_info['remaining_month'] = months_difference
                user_info['plan'] = stripe_plan[current_stripe_plan_id]
                user_info['plan_expire'] = time_expire
                user_info['interval'] = interval_count
                user_info['status'] = 'active'
                user_info['sub'] = subscribe
                
                print(">>>>>>>>>>>>>>>>>>>>> active & charge next cycle", user_info)
                return render_template('subscription.html', user_info=user_info)

            else:
                user_info['plan'] = 'Free Plan'
                user_info['plan_expire'] = 'N/A'
                user_info["interval"] = 0
            return render_template('subscription.html', user_info=user_info)
            
        user_info['plan'] = 'Free Plan'
        user_info['plan_expire'] = 'N/A'
        user_info["interval"] = 0
        return render_template('subscription.html', user_info=user_info)
    else:
        user_info['plan'] = 'Free Plan'
        user_info['plan_expire'] = 'N/A'
        user_info["interval"] = 0

        print(">>>>>>>>>>>> free",user_info)
        return render_template('subscription.html', user_info=user_info)

    return render_template('subscription.html', user_info=user_info)
@application.route('/instructor')
def instructor():
    is_sub = False
    if 'auth0_user_id' in session:
        auth0_user_id = session['auth0_user_id']
        if auth0_user_id:
            if has_stripe_id(auth0_user_id):
                stripe_customer_id = get_stripe_customer_id_from_auth0_user_id(auth0_user_id)
                if check_customer_has_subscription(stripe_customer_id):
                    subscriptions = stripe.Subscription.list(customer=stripe_customer_id, status='active')
                    if not subscriptions["data"]:
                        is_sub = False
                    else:
                        print("???????????????????????>")
                        print(subscriptions)
                        try:
                            active_subscription = subscriptions.data[0]
                            plan_id = active_subscription.plan.id
                            plan_name = stripe_plan[plan_id]
                            if plan_name == "Premium Plan":
                                is_sub = True
                        except Exception as e:
                            print(f"Error : {e}")

    instructor_option = instruct_post_options_lst()
    instructor_post = load_instructor_posts()
    instructor_post.sort(key=lambda x: x['timestamp'], reverse=True)

    return render_template("instructor.html", is_logged_in = is_sub, instructor_option = instructor_option, instructor_post = instructor_post)

@application.route('/instructor/instructor_post', methods=['GET', 'POST'])
def instructor_post():
    if 'has_active' not in session:
        return redirect(url_for('home', _scheme='https', _external=True))

    instructor_option = instruct_post_options_lst()
    
    if request.method == 'POST':

        posts = load_instructor_posts()
        new_id = len(posts)  # Generate a new id for the comment
        timestamp_utc = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')  # ISO 8601 format

        ins_type = request.form.get('type')

        area = request.form.get('area')

        ins_location = request.form.getlist("teaching")

        certificate = request.form.getlist('certificate')

        contact_method = request.form.get("contact_method") + request.form.get("custom-contact-method")


        post_text = request.form.get("extra_info")

        images = request.files.getlist('images')
        images_filenames = []
        for image in images:
            if image and allowed_file(image.filename):
                # Secure the filename before storing it
                filename = str(new_id) + '_' + secure_filename(image.filename)
                # Read the image file in binary mode
                image_data = image.read()
                # You can now save the image data to S3 or process it as needed
                # For example, to save to S3:
                try:
                    s3.put_object(
                        Bucket = INSTRUCTOR_POST_IMAGE_BUCKET,
                        Key=filename,
                        Body=image_data,
                        ContentType=image.content_type
                    )
                except Exception as e:
                    # Handle exceptions
                    print(f"Error while uploading image {filename}: {e}")
                
                image_filename = f"{s3.meta.endpoint_url}/{INSTRUCTOR_POST_IMAGE_BUCKET}/{filename}"
                images_filenames.append(image_filename)
                
        ins_post = {

            'Type': ins_type,
            'Area': area,
            "Teaching Resorts": ins_location,
            'Certification': certificate,
            'Contact Method': contact_method,

            'Images' : images_filenames,
            'id': new_id,
            'text': post_text,
            'timestamp': timestamp_utc  # Add the timestamp to the comment
        }  # Initialize counts to 0
        posts.append(ins_post)

        save_instructor_post(posts)  # Call save_comments function here

        return redirect(url_for('instructor', _scheme='https', _external=True))
    return render_template("instructor_post.html", instructor_option = instructor_option)

def save_instructor_post(posts):
    file_path = f"instructor_posts.json"
    print("save_comments:  ", file_path)
    try:
        s3.put_object(
            Body = json.dumps(posts),
            Bucket = INSTRUCTOR_POST_BUCKET,
            Key = file_path,
            ContentType = 'application/json'
        )
        print("Posts successfully saved.")
    except Exception as e:
        print(f"Error while saving Posts: {e}")

def load_instructor_posts():
    posts_file_path = f"instructor_posts.json"

    try:
        # Load comments from S3
        response = s3.get_object(Bucket = INSTRUCTOR_POST_BUCKET, Key = posts_file_path)
        posts = json.loads(response['Body'].read().decode())
    except Exception as e:
        posts = []

    return posts

@application.route('/used_gear')
def used_gear():
    if 'has_active' not in session:
        return redirect(url_for('home', _scheme='https', _external=True))
    used_gear_posts = load_used_gear_posts()
    used_gear_posts.sort(key=lambda x: x['timestamp'], reverse=True)
    used_gear_options = used_gear_option_lst()

    return render_template("used_gear.html", used_gear_posts = used_gear_posts, used_gear_options = used_gear_options, list_of_gear_for_filter= list_of_gear_for_filter)

@application.route('/used_gear/use_gear_post', methods=['GET', 'POST'])
def used_gear_post():
    if 'has_active' not in session:
        return redirect(url_for('home', _scheme='https', _external=True))

    used_gear_options = used_gear_option_lst()

    if request.method == 'POST':
        
        posts = load_used_gear_posts()
        new_id = len(posts)  # Generate a new id for the comment
        timestamp_utc = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')  # ISO 8601 format

        images = request.files.getlist('images')
        images_filenames = []
        for image in images:
            if image and allowed_file(image.filename):
                # Secure the filename before storing it
                filename = str(new_id) + '_' + secure_filename(image.filename)
                # Read the image file in binary mode
                image_data = image.read()
                # You can now save the image data to S3 or process it as needed
                # For example, to save to S3:
                try:
                    s3.put_object(
                        Bucket = USED_GEAR_IMAGE_BUCKET,
                        Key=filename,
                        Body=image_data,
                        ContentType=image.content_type
                    )
                except Exception as e:
                    # Handle exceptions
                    print(f"Error while uploading image {filename}: {e}")

                image_filename = f"{s3.meta.endpoint_url}/{USED_GEAR_IMAGE_BUCKET}/{filename}"
                images_filenames.append(image_filename)

        market_type = request.form.get('type')
        area = request.form.get('area')
        location = request.form.get("location")
        if location == "Other:":
            location += request.form.get("custom-location")
        trade = request.form.get('trade')
        if trade == "Other:":
            trade += request.form.get("custom-trade")

        len_gears = len(used_gear_options["List of Gears"])
        contact_method = request.form.get("contact_method") + request.form.get("custom-contact-method")
        list_of_gears = []
        for i in range(len_gears):
            current_index = i + 1
            gear_name = "custom-price-input-" + str(current_index)
            first_box_result = request.form.get(gear_name)
            if current_index <= 9 and first_box_result != None:
                list_of_gears.append({refer_gears[str(current_index)] : first_box_result})
            
            if current_index == 10 and first_box_result != None:
                second_box = gear_name + '-secondbox'
                second_box_result = request.form.get(second_box)
                list_of_gears.append({refer_gears[str(current_index)] : {second_box_result:first_box_result}})

        if list_of_gears == []:
            list_of_gears = None

        post_text = request.form.get("extra_info")
        gear_post = {

            'Type': market_type,
            'Area': area,
            "Location": location,
            'Trade method': trade,
            'List of Gears' : list_of_gears,
            'Contact Method' : contact_method,

            'Images': images_filenames,
            'id': new_id,
            'text': post_text,
            'timestamp': timestamp_utc  # Add the timestamp to the comment
        }  # Initialize counts to 0
        posts.append(gear_post)
        save_used_gear_post(posts)  # Call save_comments function here

        return redirect(url_for('used_gear', _scheme='https', _external=True))
    return render_template("used_gear_post.html", used_gear_options = used_gear_options)

def save_used_gear_post(posts):
    file_path = f"used_gear_posts.json"
    print("save_comments:  ", file_path)
    try:
        s3.put_object(
            Body = json.dumps(posts),
            Bucket = USED_GEAR_BUCKET,
            Key = file_path,
            ContentType = 'application/json'
        )
        print("Posts successfully saved.")
    except Exception as e:
        print(f"Error while saving Posts: {e}")

def load_used_gear_posts():
    posts_file_path = f"used_gear_posts.json"
    # counters_file_path = f"{resort_name}_counters.json"
    try:
        # Load comments from S3
        response = s3.get_object(Bucket=USED_GEAR_BUCKET, Key=posts_file_path)
        posts = json.loads(response['Body'].read().decode())
    except Exception as e:
        posts = []

    return posts

@application.route('/carpool')
def carpool():
    if 'has_active' not in session:
        return redirect(url_for('home', _scheme='https', _external=True))
    
    posts = load_carpool_posts()
    posts.sort(key=lambda x: x['timestamp'], reverse=True)
    post_options =  carpool_option_lst()
    # filter_value = request.args.get('filter_value', None)
    return render_template("carpool.html", posts = posts, post_options = post_options)

# Add this new route for the Carpool Post page
@application.route('/carpool/carpool_post' , methods=['GET', 'POST'])
def carpool_post():
    if 'has_active' not in session:
        return redirect(url_for('home', _scheme='https', _external=True))
    
    carpool_option = carpool_option_lst()
    if request.method == 'POST':

        posts = load_carpool_posts()
        new_id = len(posts)  # Generate a new id for the comment
        timestamp_utc = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')  # ISO 8601 format

        carpool_type = request.form.get('type')

        area = request.form.get('area')

        carpool_from = request.form.get("from")
        if carpool_from == "Other:":
            carpool_from += request.form.get("from-location")

        carpool_to = request.form.get('to')
        if carpool_to == "Other:":
            carpool_to += request.form.get("to-location")

        people = request.form.get('number_of_people')

        carpool_date = request.form.get('date')
        if carpool_date == "Other:":
            carpool_date += request.form.get("custom-ski-date")

        deaprt_hour = request.form.get("depart_hour")
        if deaprt_hour == "Other:":
            deaprt_hour += request.form.get("custom-depart-hour")

        return_hour = request.form.get("return_hour")
        if return_hour == "Other:":
            return_hour += request.form.get("custom-return-hour")

        money = request.form.get("expected_pay")
        if money == "Other:":
            money += request.form.get("custom-price-rate")

        contact_method = request.form.get("contact_method") + request.form.get("custom-contact-method")

        post_text = request.form.get("extra_info")
        carpool_post = {

            'Type': carpool_type,
            'Area': area,
            "From": carpool_from,
            'To': carpool_to,
            'Number of People': people,
            'Date': carpool_date,
            "Depart": deaprt_hour,
            "Return Hour (Optional)": return_hour,
            "Expected Pay / Avialable Budget (For every person) ": money,
            "Contact Method": contact_method,

            'id': new_id,
            'text': post_text,
            'timestamp': timestamp_utc  # Add the timestamp to the comment
        }  # Initialize counts to 0
        posts.append(carpool_post)
        save_carpool_post(posts)  # Call save_comments function here

        return redirect(url_for('carpool', _scheme='https', _external=True))
    return render_template("carpool_post.html", carpool_options = carpool_option)

def save_carpool_post(posts):
    file_path = f"carpool_posts.json"
    print("save_comments:  ", file_path)
    try:
        s3.put_object(
            Body=json.dumps(posts),
            Bucket=CARPOOL_BUCKET,
            Key=file_path,
            ContentType='application/json'
        )
        print("Posts successfully saved.")
    except Exception as e:
        print(f"Error while saving Posts: {e}")

def load_carpool_posts():
    posts_file_path = f"carpool_posts.json"

    try:
        # Load comments from S3
        response = s3.get_object(Bucket=CARPOOL_BUCKET, Key=posts_file_path)
        posts = json.loads(response['Body'].read().decode())
    except Exception as e:
        posts = []

    return posts

@application.route('/resort/<resort_name>')
def resort_page(resort_name):
    # if 'profile' not in session:
    #     return redirect(url_for('home', _scheme='https', _external=True)) 
    resort_comments = load_comments(resort_name)
    comment_options = comment_option_lst()

    sort_order = request.args.get('sort', 'time_desc')  # Default sort: latest to oldest
    filter_category = request.args.get('filter_category', None)
    filter_value = request.args.get('filter_value', None)

    if sort_order == 'time_asc':
        resort_comments.sort(key=lambda x: x['timestamp'])
    elif sort_order == 'time_desc':
        resort_comments.sort(key=lambda x: x['timestamp'], reverse=True)
    elif sort_order == 'yes_asc':
        resort_comments.sort(key=lambda x: x['yes_count'])
    elif sort_order == 'yes_desc':
        resort_comments.sort(key=lambda x: x['yes_count'], reverse=True)
    # Load the counters for the resort
    counters_file_path = f"{resort_name}_counters.json"
    try:
        response = s3.get_object(Bucket=COUNTER_BUCKET, Key=counters_file_path)
        counters = json.loads(response['Body'].read().decode())
    except Exception as e:
        print(f"Error while loading counters: {e}")
        counters = {}

    # Apply filtering if both filter_category and filter_value are provided
    if filter_category and filter_value:
        resort_comments = [comment for comment in resort_comments if str(comment.get(filter_category)) == filter_value]

    # Get unique filter values for the selected category
    unique_filter_values = set()
    if filter_category:
        unique_filter_values = set(comment.get(filter_category) for comment in resort_comments if comment.get(filter_category))

    # Add the counters to the comments
    for comment in resort_comments:
        comment_id = str(comment['id'])
        comment['yes_count'] = counters.get(comment_id, {}).get('yes', 0)
        comment['no_count'] = counters.get(comment_id, {}).get('no', 0)

    # Render the resort page with comments and counters
    return render_template('resort.html', resort_name=resort_name, live_camera_links=live_camera_links, comments=resort_comments, snow_forecast_links=snow_forecast_links, sort_order=sort_order, filter_category=filter_category, unique_filter_values=unique_filter_values, comment_options=comment_options)


@application.route('/resort/<resort_name>/post_comment', methods=['GET', 'POST'])
def post_comment(resort_name):
    # if 'profile' not in session:
    #     return redirect(url_for('home', _scheme='https', _external=True)) 
    comment_options = comment_option_lst()

    if request.method == 'POST':
        new_id = len(comments.get(resort_name, [])) 
        comment_text = request.form.get('comment', '').strip()
        images = request.files.getlist('images')
        images_filenames = []
        for image in images:
            if image and allowed_file(image.filename):
                # Secure the filename before storing it
                filename = str(new_id) + '_' + secure_filename(image.filename)
                # Read the image file in binary mode
                image_data = image.read()
                # You can now save the image data to S3 or process it as needed
                # For example, to save to S3:
                try:
                    s3.put_object(
                        Bucket = IMAGE_BUCKET,
                        Key=filename,
                        Body=image_data,
                        ContentType=image.content_type
                    )
                except Exception as e:
                    # Handle exceptions
                    print(f"Error while uploading image {filename}: {e}")

                image_filename = f"{s3.meta.endpoint_url}/{IMAGE_BUCKET}/{filename}"
                images_filenames.append(image_filename)

        timestamp_utc = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')  # ISO 8601 format

        road = request.form.get('Road Condition')
        lift = request.form.get('lift')
        lift_waiting_time = request.form.get('Lift Waitting Time')
        trails = request.form.getlist("trails[]")
        snow_condition = request.form.get('snow_condition')
        visibility = request.form.get('Visibility')
        weather = request.form.get('Weather')
        overall_experience = request.form.get("Overall Experience")
        comment = {
            'Road Condition' : road,
            'lift': lift,
            'Lift Waitting Time': lift_waiting_time,
            "trails": trails,
            'snow_condition': snow_condition,
            'Visibility': visibility,
            'Weather': weather,
            "Overall Experience": overall_experience,

            'id': new_id,
            'text': comment_text,
            'Images': images_filenames,
            'yes_count': 0,
            'no_count': 0,
            'timestamp': timestamp_utc  # Add the timestamp to the comment
        }  # Initialize counts to 0
        resort_comments = load_comments(resort_name)
        resort_comments.append(comment)
        save_comments(resort_name, resort_comments)  # Call save_comments function here

        # Load the existing counters
        counters_file_path = f"{resort_name}_counters.json"
        try:
            response = s3.get_object(Bucket=COUNTER_BUCKET, Key=counters_file_path)
            counters = json.loads(response['Body'].read().decode())
        except Exception as e:
            counters = {}  # If the counters file does not exist, initialize an empty dictionary

        # Add the new comment's counter to the counters
        counters[str(new_id)] = {'yes': comment['yes_count'], 'no': comment['no_count']}

        # Save the updated counters back to S3
        s3.put_object(
            Body=json.dumps(counters),
            Bucket=COUNTER_BUCKET,
            Key=counters_file_path,
            ContentType='application/json'
        )

        return redirect(url_for('resort_page', resort_name=resort_name, _scheme='https', _external=True))
    return render_template("post_comment.html", resort_name=resort_name, comment_options=comment_options)


def load_comments(resort_name):
    comments_file_path = f"{resort_name}_comments.json"
    counters_file_path = f"{resort_name}_counters.json"
    try:
        # Load comments from S3
        response = s3.get_object(Bucket=COMMENT_BUCKET, Key=comments_file_path)
        comments = json.loads(response['Body'].read().decode())
        for index, comment in enumerate(comments):
            comment['id'] = index  # Assign a unique id to each comment

            # Load counters from S3
            response = s3.get_object(Bucket=COUNTER_BUCKET, Key=counters_file_path)
            counters = json.loads(response['Body'].read().decode())

            # Add the counters to the comments
            comment_id = comment.get('id', None)  # Use get method to avoid KeyError
            if comment_id is not None:
                comment['road'] = comment.get('Road Condition', None)
                comment['yes_count'] = counters.get(str(comment_id), {}).get('yes', 0)
                comment['no_count'] = counters.get(str(comment_id), {}).get('no', 0)
                comment['lift'] = comment.get('lift', None)
                comment['lift_waiting_time'] = comment.get('Lift Waitting Time', None)
                comment['trails'] = comment.get('trails', None)
                comment['snow_condition'] = comment.get('snow_condition', None)
                comment['Visibility'] = comment.get('Visibility', None)
                comment['Weather'] = comment.get('Weather', None)
                comment['overall_experience'] = comment.get("Overall Experience", None)
            else:
                # Handle the case where 'id' is missing from the comment
                comment['road'] = None
                comment['yes_count'] = 0
                comment['no_count'] = 0
                comment['lift'] = None
                comment['Lift Waitting Time'] = None
                comment["trails"] = None
                comment['snow_condition'] = None
                comment['Visibility'] = None
                comment['Weather'] = None
                comment['Overall Experience'] = None
    except Exception as e:
        comments = []

    return comments

    
def save_comments(resort_name, comments):
    file_path = f"{resort_name}_comments.json"
    print("save_comments:  ", file_path)
    try:
        s3.put_object(
            Body=json.dumps(comments),
            Bucket=COMMENT_BUCKET,
            Key=file_path,
            ContentType='application/json'
        )
        print("Comments successfully saved.")
    except Exception as e:
        print(f"Error while saving comments: {e}")


@application.route('/save_counters_route', methods=['POST'])
def save_counters_route():
    try:
        data = request.get_json()
        resort_name = data['resort_name']
        comment_id = data['comment_id']
        action = data['action']
        vote_type = data['type']

        counters_file_path = f"{resort_name}_counters.json"
        try:
            # Load counters from S3
            response = s3.get_object(Bucket=COUNTER_BUCKET, Key=counters_file_path)
            counters = json.loads(response['Body'].read().decode())
        except Exception as e:
            print(f"Error while loading counters: {e}")
            counters = {}
        
        if str(comment_id) not in counters:
            counters[str(comment_id)] = {'yes': 0, 'no': 0}

        if action == 'increment':
            counters[str(comment_id)][vote_type] += 1
        elif action == 'decrement':
            counters[str(comment_id)][vote_type] = max(counters[str(comment_id)][vote_type] - 1, 0)

        # Save counters to S3
        s3.put_object(
            Body=json.dumps(counters),
            Bucket=COUNTER_BUCKET,
            Key=counters_file_path,
            ContentType='application/json'
        )

        return jsonify({
            'message': 'Counters updated successfully',
            'yes_count': counters[str(comment_id)]['yes'],
            'no_count': counters[str(comment_id)]['no']
        })
    except Exception as e:
        logging.error(f"Error fetching user info: {e}")
        return jsonify({'error': str(e)}), 400

@application.route('/save_counters', methods=['POST'])
@limiter.limit("15/minute")
def save_counters(resort_name, counters):
    counters_file_path = f"{resort_name}_counters.json"
    try:
        s3.put_object(
            Body=json.dumps(counters),
            Bucket=COUNTER_BUCKET,
            Key=counters_file_path,
            ContentType='application/json'
        )
        print("Counters successfully saved.")
    except Exception as e:
        print(f"Error while saving counters: {e}")


def store_all_counters():
    for resort_name, resort_comments in comments.items():
        counters = {}
        for comment in resort_comments:
            comment_id = comment.get('id')
            counters[str(comment_id)] = {'yes': comment.get('yes_count', 0), 'no': comment.get('no_count', 0)}
        save_counters(resort_name, counters)

    print("Counters saved successfully.") 

def read_all_resort():
    objects = s3.list_objects_v2(Bucket = COMMENT_BUCKET)
    json_files = [obj['Key'] for obj in objects.get('Contents', []) if obj['Key'].endswith('.json')]
    resort_data = {}
    for file_key in json_files:
        response = s3.get_object(Bucket=COMMENT_BUCKET, Key=file_key)
        file_content = response['Body'].read()
        json_content = json.loads(file_content)
        resort_name = re.sub(r'_comments\.json$', '', file_key).replace('_', ' ')
    
        resort_data[resort_name] = json_content
    
    all_resort_condition = {}
    for current_resort_name in resort_data.keys():
        count = {'Good' : 0, 'Normal' : 0, 'Bad' : 0}
        for comment in resort_data[current_resort_name]:
            if comment["Overall Experience"] != '':
                if comment["Overall Experience"] == 'Good':
                    count['Good'] += 1
                elif comment['Overall Experience'] == 'Normal':
                    count['Normal'] += 1
                else:
                    count['Bad'] += 1
        max_key = max(count, key = count.get)
        all_resort_condition[current_resort_name] = max_key
    for key in area_mountain_ref.keys():
        for area_mountain in area_mountain_ref[key]:
            if area_mountain not in all_resort_condition.keys():
                all_resort_condition[area_mountain] = "NA"
    print(all_resort_condition)
    return all_resort_condition

area_mountain_ref = { 
        "Toronto": [
            "Blue Mountain", 
            "Snow Valley", 
            "Horseshoe Resort", 
            "Hockley Valley Resort", 
            "Mount St Louis",
        ],
        "Vancouver": [
            "Cypress Mountain", 
            "Whistler Blackcomb", 
            "Grouse Mountain", 
            "Mount Seymour",
        ]
    }
        

comments = {
    'Cypress_Mountain': load_comments('Cypress_Mountain'),
    'Grouse_Mountain': load_comments('Grouse_Mountain'),
    'Whistler_Blackcomb': load_comments('Whistler_Blackcomb'),
    'Mount_Seymour': load_comments('Mount_Seymour'),
    'Blue_Mountain': load_comments('Blue_Mountain'),
    'Snow_Valley': load_comments('Snow_Valley'),
    'Mount_St_Louis': load_comments('Mount_St_Louis'),
    'Hockley_Valley_Resort': load_comments('Hockley_Valley_Resort'),
    'Horseshoe_Resort': load_comments('Horseshoe_Resort')
}

refer_gears = {
    '1' : "Skis",
    '2' : "Snowboard",
    '3' : "Bingdings",
    '4' : "Boots->Skis",
    '5' : "Boots->Snowboard",
    '6' : "Helmets",
    '7' : "Poles",
    '8' : "Apparel & Outerwear",
    '9' : "Protective Gear",
    '10' : "Other:"
}

list_of_gear_for_filter = {
    "List of Gears": ["Skis", "Snowboard", "Bingdings", "Boots->Skis", "Boots->Snowboard", "Helmets", "Poles", "Apparel & Outerwear", "Protective Gear", "Other:"]
}

posts = load_carpool_posts()

if __name__ == '__main__':
    application.run(debug=True,host='127.0.0.1', port=8000)
# if __name__ == '__main__':
#     application.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
