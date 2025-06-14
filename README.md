🛒 E-Commerce Data Finder 🔍

A powerful web-based tool to fetch product and store data from the internet using Google Search via SerpAPI. Now enhanced with Google Sign-In, advanced website filters, and map visualizations to improve the e-commerce data exploration experience.

✨ Features

🔐 Google Sign-In
Sign in using your Google account via Firebase Authentication or OAuth 2.0.

🌐 Google Search API (SerpAPI) Integration
Search for product or store names and fetch real-time e-commerce data.

🧠 Smart Filters on Fetched Results
domain_active: Only show websites that are currently live and reachable.

shopify: Detect and filter Shopify-based stores.

loads_in_5s: Exclude websites that are slow to load.

Email & Phone Extraction: Automatically extract and show contact information (email and phone) from websites.

Social media links scraper

🗺️ Map & Geo Visualization
Show store locations on an interactive map (using Google Maps or Leaflet).

Map clustering for better visualization of multiple locations.

📂 Upload & Export
Upload search queries in bulk

Export fetched data to CSV

See history of searches and downloads (coming soon)

📦 Result Data Includes:

Title

URL

Description

Store Type

Emails and Phone Numbers

Google Map Link (based on location if found)

🧱 Folder Structure

ecommerce-data-finder/
├── app.py                      # Flask backend
├── templates/
│   └── index.html              # Main HTML interface
├── static/
│   ├── script.js               # JavaScript for UI logic and API calls
│   ├── map.js                  # Map rendering logic (Leaflet.js / Google Maps)
│   └── style.css               # Optional custom styles
├── uploads/                   # Uploaded files directory
├── csv_files/                 # Generated CSVs
├── results/                   # Fetched results
├── geo_data.json              # Location metadata
├── firebase_auth.js           # Google sign-in logic
└── requirements.txt           # Python dependencies
🔧 Setup Instructions

1. Clone and install dependencies
   
git clone https://github.com/DiyaWalvekar/Ecommerce-Finder.git
cd ecommerce-data-finder
pip install -r requirements.txt

3. Add your SerpAPI Key

Update app.py with your SerpAPI key:
SERP_API_KEY = "your-serpapi-key"

5. Configure Google Sign-In
   
Use Firebase Authentication

Or set up OAuth 2.0 via Google Cloud Console and update firebase_auth.js

6. Run your app
   
python app.py
Visit: http://127.0.0.1:5000

📊 Filtering Logic (Backend Support Required)

Filter	Description

domain_active	Checks if website is currently reachable (HTTP 200/OK)
shopify	Looks for Shopify-related meta tags
loads_in_5s	Uses requests timing to filter slow sites
emails & phones	Regex-based scraping of emails and phone numbers
map_link	Uses Google Geocoding API (or OpenStreetMap) to create links

🧪 Sample Workflow

Sign in with Google

Enter a product or store name

See results with filters & map view

Export to CSV or copy email/phone

Click View on Map for directions

🔮 Future Improvements

Search history and download history (user-wise)

Live preview of stores in iframe modal

Mobile-responsive interface

📦 Requirements

Flask
requests
serpapi
beautifulsoup4
geopy
firebase-admin (for Google Auth)
python-dotenv
Install via:


pip install -r requirements.txt

🧑‍💻 Author
Diya Walvekar

Student @ KLE Institute of Technology
