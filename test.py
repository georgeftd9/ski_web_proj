from flask import Flask, render_template, request, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
import os
import binascii
import json
from flask import session, flash
from datetime import datetime, timedelta


secret_key = os.urandom(24)
secret_key_hex = binascii.hexlify(secret_key).decode('utf-8')
print("Secret key is: ", secret_key_hex)
app = Flask(__name__)
snow_forecast_links = {
    'Cypress_Mountain': 'https://www.snow-forecast.com/resorts/Cypress-Mountain/6day/mid',
    'Grouse_Mountain': 'https://www.snow-forecast.com/resorts/Grouse-Mountain/6day/mid',
    'Whistler_Blackcomb': 'https://www.snow-forecast.com/resorts/Whistler-Blackcomb/6day/mid',
    'Mount_Seymour': 'https://www.snow-forecast.com/resorts/Mount-Seymour/6day/mid'
}
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['COMMENTS_DIR'] = 'static/comments/'  # Specify the directory to store comments
app.config['COMMENTS_COUNTER'] = 'static/comments_counter/'
app.secret_key = secret_key

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/resort/<resort_name>')
def resort_page(resort_name):
    # Load the comments for the resort
    resort_comments = load_comments(resort_name)

    # Load the counters for the resort
    counters_file_path = os.path.join(app.config['COMMENTS_COUNTER'], f"{resort_name}_counters.json")
    if os.path.exists(counters_file_path):
        with open(counters_file_path, 'r') as file:
            counters = json.load(file)
    else:
        counters = {}

    # Add the counters to the comments
    for comment in resort_comments:
        comment_id = str(comment['id'])
        comment['yes_count'] = counters.get(comment_id, {}).get('yes', 0)
        comment['no_count'] = counters.get(comment_id, {}).get('no', 0)

    # Render the resort page with comments and counters
    return render_template('resort.html', resort_name=resort_name, comments=resort_comments, snow_forecast_links=snow_forecast_links)

@app.route('/resort/<resort_name>/post_comment', methods=['GET', 'POST'])
def post_comment(resort_name):
    if request.method == 'POST':
        comment_text = request.form.get('comment', '').strip()
        image = request.files.get('image')
        if not comment_text and (not image or image.filename == ''):
            flash('You must share something before you post a comment, could be either text or photos.')
            return redirect(url_for('post_comment', resort_name=resort_name))
        image_filename = None
        if image and allowed_file(image.filename):
            image_filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            image_filename = os.path.join('uploads', image_filename).replace('\\', '/')
        new_id = len(comments.get(resort_name, []))  # Generate a new id for the comment
        timestamp_utc = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')  # ISO 8601 format

        comment = {
            'id': new_id,
            'text': comment_text,
            'image': image_filename,
            'yes_count': 0,
            'no_count': 0,
            'timestamp': timestamp_utc  # Add the timestamp to the comment
        }  # Initialize counts to 0
        comments.setdefault(resort_name, []).append(comment)
        save_comments(resort_name, comments[resort_name])  # Call save_comments function here
        return redirect(url_for('resort_page', resort_name=resort_name))
    return render_template("post_comment.html", resort_name=resort_name)

def load_comments(resort_name):
    try:
        file_path = os.path.join(app.config['COMMENTS_DIR'], f"{resort_name}_comments.json")
        with open(file_path, 'r') as file:
            comments = json.load(file)
            for index, comment in enumerate(comments):
                comment['id'] = index  # Assign a unique id to each comment
    except FileNotFoundError:
        comments = []

    try:
        with open(f'static/counters/{resort_name}_counters.json', 'r') as file:
            counters = json.load(file)
    except FileNotFoundError:
        counters = {}

    for comment in comments:
        comment_id = comment.get('id', None)  # Use get method to avoid KeyError
        if comment_id is not None:
            comment['yes_count'] = counters.get(str(comment_id), {}).get('yes', 0)
            comment['no_count'] = counters.get(str(comment_id), {}).get('no', 0)
        else:
            # Handle the case where 'id' is missing from the comment
            comment['yes_count'] = 0
            comment['no_count'] = 0

    print(f"Loaded comments for {resort_name}: {comments}")  # Add this line to check the loaded comments
    return comments
    
def save_comments(resort_name, comments):
    file_path = os.path.join(app.config['COMMENTS_DIR'], f"{resort_name}_comments.json")
    try:
        with open(file_path, 'w') as file:
            json.dump(comments, file)
        print("Comments successfully saved.")
    except Exception as e:
        print(f"Error while saving comments: {e}")

@app.route('/save_counters', methods=['POST'])
def save_counters_route():
    try:
        data = request.get_json()
        resort_name = data['resort_name']
        comment_id = data['comment_id']
        action = data['action']
        vote_type = data['type']

        counters_file_path = os.path.join(app.config['COMMENTS_COUNTER'], f"{resort_name}_counters.json")
        if os.path.exists(counters_file_path):
            with open(counters_file_path, 'r') as file:
                counters = json.load(file)
        else:
            counters = {}

        if str(comment_id) not in counters:
            counters[str(comment_id)] = {'yes': 0, 'no': 0}

        if action == 'increment':
                counters[str(comment_id)][vote_type] += 1
        elif action == 'decrement':
            counters[str(comment_id)][vote_type] = max(counters[str(comment_id)][vote_type] - 1, 0)

        with open(counters_file_path, 'w') as file:
            json.dump(counters, file)

        return jsonify({
            'message': 'Counters updated successfully',
            'yes_count': counters[str(comment_id)]['yes'],
            'no_count': counters[str(comment_id)]['no']
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

def save_counters(resort_name, counters):
    counters_file_path = os.path.join(app.config['COMMENTS_COUNTER'], f"{resort_name}_counters.json")
    try:
        print(f"Counters to be saved for {resort_name}: {counters}")  # Add this line to check the counters before saving
        with open(counters_file_path, 'w') as file:
            json.dump(counters, file)
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

comments = {
    'Cypress_Mountain': load_comments('Cypress_Mountain'),
    'Grouse_Mountain': load_comments('Grouse_Mountain'),
    'Whistler_Blackcomb': load_comments('Whistler_Blackcomb'),
    'Mount_Seymour': load_comments('Mount_Seymour')
}

if __name__ == '__main__':
    app.run(debug=True)