import os
import re
import csv
import time
import json
import requests
import phonenumbers
from flask_cors import CORS
from flask import Flask, request, jsonify, send_from_directory, render_template
from werkzeug.utils import secure_filename
from serpapi import GoogleSearch
from flask import Flask, request, jsonify, render_template, redirect, session, flash
from authlib.integrations.flask_client import OAuth
from flask import url_for
from werkzeug.security import generate_password_hash, check_password_hash
from get_db_connection import get_mysql_connection
from urllib.parse import urlparse

app = Flask(__name__)

# Config folders
UPLOAD_FOLDER = "uploads"
CSV_FOLDER = "csv_files"
RESULT_FOLDER = "results"
MAP_DATA_FILE = "geo_data.json"

# API keys
SERPAPI_KEY = "your-serp-api"
GOOGLE_MAPS_API_KEY = "your-GOOGLE_MAPS_API_KEY"
GOOGLE_PLACES_API_KEY = "your-GOOGLE_PLACES_API_KEY"


EMAIL_REGEX = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

# Create folders
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(CSV_FOLDER, exist_ok=True)
os.makedirs(RESULT_FOLDER, exist_ok=True)

from math import radians, cos, sin, asin, sqrt
app = Flask(__name__)
app.secret_key = '383113752acaa61025fc92b979753a5b'

CORS(app)

# OAuth Setup


oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='563937633548-uul7b3jm6a0snhe03mpp0ikusub6ekl2.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
    },

)

import secrets

@app.route('/login/google')
def login_google():
    # Generate a secure random nonce and save in session
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce

    redirect_uri = url_for('authorize_google', _external=True)
    # Pass nonce param to authorize_redirect so Google includes it in ID token
    return google.authorize_redirect(redirect_uri, nonce=nonce)


@app.route('/login/google/callback')
def authorize_google():
    # Step 1: Get token after Google OAuth callback
    token = google.authorize_access_token()

    # Step 2: Retrieve nonce from session for validation
    nonce = session.get('nonce')
    if not nonce:
        flash('Invalid login attempt: missing nonce.', 'error')
        return redirect('/login')

    # Step 3: Parse ID token to get user info (email, name, etc.)
    user_info = google.parse_id_token(token, nonce=nonce)
    user_email = user_info['email']

    # Step 4: Connect to your MySQL DB and check if user exists
    conn = get_mysql_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = %s", (user_email,))
    user = cursor.fetchone()

    if not user:
        # User doesn't exist - create new user with random password hash
        cursor.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)",
            (user_email, generate_password_hash(os.urandom(16).hex()))
        )
        conn.commit()

    cursor.close()
    conn.close()

    # Step 5: Store user email in session and flash message
    session['user'] = user_email
    flash('Logged in successfully using Google!', 'success')

    # Step 6: Redirect user to your index/home page
    return redirect('/index')


def geocode_location(address, api_key):
    url = f"https://maps.googleapis.com/maps/api/geocode/json?address={address}&key={api_key}"
    response = requests.get(url)
    data = response.json()
    if data["status"] == "OK":
        location = data["results"][0]["geometry"]["location"]
        lat, lng = location["lat"], location["lng"]
        maps_link = f"https://www.google.com/maps?q={lat},{lng}"
        return lat, lng, maps_link
    return None, None, None

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')

@app.route('/')
def home():
    return render_template('home.html')  # home.html should have login and signup links in header

@app.route('/index')
def index():
    if 'user' not in session:
        return redirect('/login')
    return render_template('index.html')

def get_user_location():
    try:
        response = requests.get("https://ipapi.co/json/")
        data = response.json()
        return float(data['latitude']), float(data['longitude'])
    except:
        return None, None

def calculate_distance(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2):
        return None
    lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
    dlon = lon2 - lon1 
    dlat = lat2 - lat1 
    a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
    c = 2 * asin(sqrt(a)) 
    km = 6371 * c
    return round(km, 2)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        conn = get_mysql_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and check_password_hash(user['password'], password_input):
            session['user'] = user['email']
            return redirect('/index')
        else:
            flash("Invalid email or password", "error")

    return render_template("login.html")

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        try:
            conn = get_mysql_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password))
            conn.commit()
            cursor.close()
            conn.close()
            flash("Signup successful. Please log in.", "success")
            return redirect('/login')
        except:
            flash("Email already exists or error occurred.", "error")

    return render_template("signup.html")

GOOGLE_MAPS_API_KEYS = [
    "AIzaSyBTSdEG2fWO_ioa2gYklRt4jk4T30dNzMc",
    # Add more keys below if available
    # "AIzaSyB-AnotherKey",
]

def geocode_location_with_fallback(address):
    for key in GOOGLE_MAPS_API_KEYS:
        try:
            url = f"https://maps.googleapis.com/maps/api/geocode/json?address={address}&key={key}"
            response = requests.get(url)
            data = response.json()

            if data["status"] == "OK":
                location = data["results"][0]["geometry"]["location"]
                lat, lng = location["lat"], location["lng"]
                maps_link = f"https://www.google.com/maps?q={lat},{lng}"
                return lat, lng, maps_link
            else:
                print(f"[Geocode Fail] {address} | Status: {data['status']}")
        except Exception as e:
            print(f"[Exception] Geocoding failed for {address}: {str(e)}")
    return None, None, None

import re
import requests

def extract_social_links(html_text):
    patterns = {
        "LinkedIn": r"https?://(?:www\.)?linkedin\.com/[^\s\"'>]+",
        "Twitter": r"https?://(?:www\.)?twitter\.com/[^\s\"'>]+",
        "Facebook": r"https?://(?:www\.)?facebook\.com/[^\s\"'>]+",
        "Instagram": r"https?://(?:www\.)?instagram\.com/[^\s\"'>]+"
    }
    found_links = {key: "" for key in patterns}
    for name, pattern in patterns.items():
        match = re.search(pattern, html_text, re.IGNORECASE)
        if match:
            found_links[name] = match.group(0)
    return found_links

def safe_value(value):
    return value if value not in [None, "", [], {}, "null"] else "Data not found"

@app.route('/fetch_websites', methods=['POST'])
def fetch_websites():
    data = request.get_json()
    country = data.get('country', '').strip()
    city = data.get('city', '').strip()
    industry = data.get('industry', '').strip()
    count = int(data.get('count', 10))

    if not all([country, city, industry]):
        return jsonify({"success": False, "error": "Missing input fields."})

    query = f"{industry} companies in {city}, {country}"
    all_links = []
    geo_data = []
    start = 0

    try:
        while len(geo_data) < count:
            params = {
                "engine": "google",
                "q": query,
                "api_key": SERPAPI_KEY,
                "start": start
            }
            search = GoogleSearch(params)
            results = search.get_dict()

            if "error" in results:
                return jsonify({"success": False, "error": results["error"]})

            organic_results = results.get("organic_results", [])
            if not organic_results:
                break

            for res in organic_results:
                link = res.get("link")
                title = res.get("title", "Data not found")

                if link and link.startswith("http") and link not in all_links:
                    all_links.append(link)
                    address_input = f"{title}, {city}, {country}"
                    lat, lng, maps_link = geocode_location_with_fallback(address_input)

                    if not lat or not lng:
                        print(f"[Skip] No valid coordinates for: {title}")
                        lat = lng = maps_link = "Data not found"

                    # Google Places API: Get place_id
                    place_search_url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json"
                    search_params = {
                        "input": address_input,
                        "inputtype": "textquery",
                        "fields": "place_id",
                        "key": GOOGLE_PLACES_API_KEY
                    }
                    place_resp = requests.get(place_search_url, params=search_params).json()
                    place_id = place_resp.get("candidates", [{}])[0].get("place_id", None)

                    rating = reviews = hours = photo_url = place_name = gmaps_place_link = address = "Data not found"

                    if place_id:
                        # Fetch detailed place info
                        details_url = "https://maps.googleapis.com/maps/api/place/details/json"
                        details_params = {
                            "place_id": place_id,
                            "fields": "name,rating,user_ratings_total,opening_hours,photos,url,formatted_address",
                            "key": GOOGLE_PLACES_API_KEY
                        }
                        detail_resp = requests.get(details_url, params=details_params).json()
                        result = detail_resp.get("result", {})

                        rating = result.get("rating", "Data not found")
                        reviews = result.get("user_ratings_total", "Data not found")
                        hours = ", ".join(result.get("opening_hours", {}).get("weekday_text", [])) if result.get("opening_hours") else "Data not found"
                        photo_ref = result.get("photos", [{}])[0].get("photo_reference", None)
                        place_name = result.get("name", title)
                        gmaps_place_link = result.get("url", maps_link)
                        address = result.get("formatted_address", address_input)

                        if photo_ref:
                            photo_url = f"https://maps.googleapis.com/maps/api/place/photo?maxwidth=800&photoreference={photo_ref}&key={GOOGLE_PLACES_API_KEY}"

                    # Fetch social media links
                    try:
                        response = requests.get(link, timeout=8, headers={"User-Agent": "Mozilla/5.0"})
                        if response.status_code != 200:
                            raise Exception("Bad status")
                        social_links = extract_social_links(response.text)
                    except Exception as e:
                        print(f"[Social Error] {link}: {e}")
                        social_links = {}

                    geo_data.append({
                        "name": safe_value(place_name),
                        "url": safe_value(link),
                        "lat": safe_value(lat),
                        "lng": safe_value(lng),
                        "maps_link": safe_value(gmaps_place_link),
                        "rating": safe_value(rating),
                        "reviews": safe_value(reviews),
                        "hours": safe_value(hours),
                        "photo_url": safe_value(photo_url),
                        "address": safe_value(address),
                        "LinkedIn": safe_value(social_links.get("LinkedIn")),
                        "Twitter": safe_value(social_links.get("Twitter")),
                        "Facebook": safe_value(social_links.get("Facebook")),
                        "Instagram": safe_value(social_links.get("Instagram"))
                    })

                    if len(geo_data) >= count:
                        break

            start += 10

        if not geo_data:
            return jsonify({"success": False, "error": "No valid geo data found."})

        # Save to CSV
        filename = f"links_{int(time.time())}.csv"
        filepath = os.path.join(CSV_FOLDER, filename)
        with open(filepath, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "Company", "Website", "Google Maps Link", "Latitude", "Longitude",
                "Rating", "Total Reviews", "Opening Hours", "Top Photo URL", "Address",
                "LinkedIn", "Twitter", "Facebook", "Instagram"
            ])
            for entry in geo_data:
                writer.writerow([
                    entry["name"],
                    entry["url"],
                    entry["maps_link"],
                    entry["lat"],
                    entry["lng"],
                    entry["rating"],
                    entry["reviews"],
                    entry["hours"],
                    entry["photo_url"],
                    entry["address"],
                    entry["LinkedIn"],
                    entry["Twitter"],
                    entry["Facebook"],
                    entry["Instagram"]
                ])

        # Save to JSON for frontend map
        with open(MAP_DATA_FILE, "w", encoding='utf-8') as jf:
            json.dump(geo_data, jf, indent=2)

        # --- ✅ Insert into history table ---
        user_id = request.headers.get('User-ID')
        if user_id:
            try:
                conn = get_mysql_connection()
                with conn.cursor() as cursor:
                    cursor.execute('''
                        INSERT INTO search_history (user_id, industry, city, country, csv_filename, record_count)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (user_id, industry, city, country, filename, len(geo_data)))
                    conn.commit()
                conn.close()
            except Exception as e:
                print(f"[DB ERROR] History insert failed: {e}")

        return jsonify({"success": True, "filename": filename})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/apply_filters', methods=['POST'])
def apply_filters():
    file = request.files.get('file')
    if not file:
        return jsonify({"success": False, "error": "No CSV file uploaded."}), 400

    domain_active = request.form.get('domainActive', 'false').lower() == 'true'
    shopify_only = request.form.get('shopifyOnly', 'false').lower() == 'true'
    load_fast = request.form.get('loadFast', 'false').lower() == 'true'

    filename = secure_filename(file.filename)
    filepath = os.path.join(CSV_FOLDER, filename)
    file.save(filepath)

    filtered_rows = []
    with open(filepath, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header:
            filtered_rows.append(header)

        for row in reader:
            url = row[1].strip() if len(row) > 1 else row[0].strip()
            if not url:
                continue

            try:
                start_time = time.time()
                resp = requests.get(url, timeout=10)
                elapsed = time.time() - start_time

                if domain_active and resp.status_code != 200:
                    continue
                if load_fast and elapsed > 5:
                    continue
                if shopify_only:
                    page_text = resp.text.lower()
                    if "myshopify.com" not in page_text and "cdn.shopify.com" not in page_text:
                        continue

                filtered_rows.append(row)

            except Exception:
                if domain_active:
                    continue
                continue

    filtered_filename = f"filtered_{filename}"
    filtered_filepath = os.path.join(CSV_FOLDER, filtered_filename)

    with open(filtered_filepath, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerows(filtered_rows)

    return jsonify({"success": True, "filename": filtered_filename})




@app.route('/fetch_emails', methods=['POST'])
def fetch_emails():
    file = request.files.get('file')
    if not file:
        return jsonify({"success": False, "error": "No file uploaded."})

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    results = []

    # Strict email regex
    EMAIL_REGEX = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}"
    ALLOWED_TLDS = {"com", "org", "net", "in", "co", "edu", "gov", "io"}

    try:
        with open(filepath, newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            url_col = next((col for col in reader.fieldnames if 'url' in col.lower() or 'website' in col.lower()), None)
            if not url_col:
                return jsonify({"success": False, "error": "No valid URL column found."})

            for row in reader:
                url = row.get(url_col, "").strip()
                if not url:
                    continue

                try:
                    resp = requests.get(url, timeout=10)
                    if resp.status_code == 200:
                        html = resp.text

                        # ---- EMAILS ----
                        raw_emails = re.findall(EMAIL_REGEX, html)
                        clean_emails = set()
                        for email in raw_emails:
                            email = email.lower().strip(".;,:'\" ")
                            domain = email.split('@')[-1]
                            tld = domain.split('.')[-1]
                            if (
                                "@" in email
                                and len(email) < 100
                                and not any(block in email for block in ['noreply', 'no-reply', 'example@'])
                                and tld in ALLOWED_TLDS
                            ):
                                clean_emails.add(email)

                        # ---- PHONES ----
                        raw_phones = set()
                        for match in phonenumbers.PhoneNumberMatcher(html, "IN"):
                            number = phonenumbers.format_number(match.number, phonenumbers.PhoneNumberFormat.E164)
                            if phonenumbers.is_valid_number(match.number):
                                raw_phones.add(number)

                        email_str = "; ".join(sorted(clean_emails)) if clean_emails else "No valid email found"
                        phone_str = "; ".join(sorted(raw_phones)) if raw_phones else "No valid phone number found"
                    else:
                        email_str = "No valid email found"
                        phone_str = "No valid phone number found"

                except Exception:
                    email_str = "Error accessing site"
                    phone_str = "Error accessing site"

                results.append({
                    "website": url,
                    "emails": email_str,
                    "phones": phone_str
                })

        output_filename = f"contact_info_{filename}"
        output_path = os.path.join(RESULT_FOLDER, output_filename)
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["website", "emails", "phones"])
            writer.writeheader()
            writer.writerows(results)

        return jsonify({"success": True, "filename": output_filename})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})



@app.route('/map')
def map_view():
    with open(MAP_DATA_FILE, 'r') as f:
        geo_data = json.load(f)
    return render_template('map.html',
                           companies=json.dumps(geo_data),
                           google_maps_api_key=GOOGLE_MAPS_API_KEY)

@app.route('/download/<filename>')
def download_file(filename):
    for folder in [CSV_FOLDER, RESULT_FOLDER, UPLOAD_FOLDER]:
        filepath = os.path.join(folder, filename)
        if os.path.exists(filepath):
            return send_from_directory(folder, filename, as_attachment=True)
    return jsonify({"success": False, "error": "File not found."}), 404

@app.route('/map_data')
def map_data():
    with open(MAP_DATA_FILE, "r", encoding='utf-8') as f:
        data = json.load(f)

    # Clean & filter valid entries
    companies = []
    for item in data:
        try:
            lat = float(item["lat"])
            lng = float(item["lng"])
            companies.append({
                "name": item["name"],
                "lat": lat,
                "lng": lng,
                "url": item["maps_link"] or item["url"]
            })
        except:
            continue

    return jsonify(companies)


if __name__ == '__main__':
    app.run(debug=True)
