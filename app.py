import sqlite3
import hashlib
import jwt
import datetime as dt
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory, render_template_string, render_template
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

DB_NAME = "database.db"
JWT_SECRET = "super-secret-key"
JWT_ALGO = "HS256"

# --- helper functions ---
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # User authentication table
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fullname TEXT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # Trips table to hold trip-level data
    c.execute("""
    CREATE TABLE IF NOT EXISTS trips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        start_date TEXT,
        end_date TEXT,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    # Notes table for notes related to a specific trip
    c.execute("""
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT,
        trip_id INTEGER,
        FOREIGN KEY(trip_id) REFERENCES trips(id) ON DELETE CASCADE
    )
    """)
    # Places to visit table
    c.execute("""
    CREATE TABLE IF NOT EXISTS places (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        date TEXT,
        description TEXT,
        trip_id INTEGER,
        FOREIGN KEY(trip_id) REFERENCES trips(id) ON DELETE CASCADE
    )
    """)
    # Itinerary table
    c.execute("""
    CREATE TABLE IF NOT EXISTS itinerary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        date TEXT,
        trip_id INTEGER,
        FOREIGN KEY(trip_id) REFERENCES trips(id) ON DELETE CASCADE
    )
    """)
    # Budget table
    c.execute("""
    CREATE TABLE IF NOT EXISTS budget (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        amount REAL NOT NULL,
        description TEXT,
        trip_id INTEGER,
        FOREIGN KEY(trip_id) REFERENCES trips(id) ON DELETE CASCADE
    )
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def issue_jwt(user_id, email):
    now = dt.datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "email": email,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(hours=24)).timestamp())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def login_required(f):
    """Decorator to protect API routes requiring authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            g.user = {"id": payload["sub"], "email": payload["email"]}
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# --- dashboard routes ---
@app.route('/')
def dashboard():
    return render_template('dashboard.html')

# --- authentication routes ---
@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    email = (data.get("email") or "").lower().strip()
    password = data.get("password") or ""
    fullname = (data.get("fullname") or "").strip()

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        if c.fetchone():
            return jsonify({"error": "Email already registered"}), 409

        password_hash = hash_password(password)
        c.execute("INSERT INTO users (fullname, email, password_hash) VALUES (?, ?, ?)", (fullname, email, password_hash))
        conn.commit()
        user_id = c.lastrowid
    finally:
        conn.close()

    token = issue_jwt(user_id, email)
    return jsonify({"token": token, "user": {"id": user_id, "email": email}})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = (data.get("email") or "").lower().strip()
    password = data.get("password") or ""

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE email = ?", (email,))
        row = c.fetchone()
    finally:
        conn.close()

    if not row or hash_password(password) != row["password_hash"]:
        return jsonify({"error": "Invalid credentials"}), 401

    token = issue_jwt(row["id"], email)
    return jsonify({"token": token, "user": {"id": row["id"], "email": email}})

@app.route("/api/me", methods=["GET"])
@login_required
def me():
    return jsonify({"id": g.user["id"], "email": g.user["email"]})

@app.route("/api/profile", methods=["GET"])
@login_required
def profile():
    conn = get_db()
    row = conn.execute("SELECT fullname, email FROM users WHERE id = ?", (g.user["id"],)).fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "fullname": row["fullname"],
        "email": row["email"]
    })

# --- trip management routes ---
@app.route("/api/trips", methods=["POST"])
@login_required
def create_trip():
    data = request.get_json()
    name = data.get("name")
    start_date = data.get("start_date")
    end_date = data.get("end_date")
    user_id = g.user["id"]

    if not name:
        return jsonify({"error": "Trip name is required"}), 400

    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO trips (name, start_date, end_date, user_id) VALUES (?, ?, ?, ?)",
                  (name, start_date, end_date, user_id))
        conn.commit()
        trip_id = c.lastrowid
        return jsonify({"id": trip_id, "name": name, "start_date": start_date, "end_date": end_date})
    finally:
        conn.close()

@app.route("/api/trips", methods=["GET"])
@login_required
def get_trips():
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id, name, start_date, end_date FROM trips WHERE user_id = ?", (user_id,))
        trips = c.fetchall()
        return jsonify([dict(trip) for trip in trips])
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>", methods=["GET"])
@login_required
def get_trip_details(trip_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT id, name, start_date, end_date FROM trips WHERE id = ? AND user_id = ?", (trip_id, user_id))
        trip = c.fetchone()
        if not trip:
            return jsonify({"error": "Trip not found or not authorized"}), 404

        trip_data = dict(trip)

        # Fetch all associated data
        c.execute("SELECT id, content FROM notes WHERE trip_id = ?", (trip_id,))
        trip_data["notes"] = [dict(row) for row in c.fetchall()]

        c.execute("SELECT id, name, date, description FROM places WHERE trip_id = ?", (trip_id,))
        trip_data["places"] = [dict(row) for row in c.fetchall()]

        c.execute("SELECT id, name, description, date FROM itinerary WHERE trip_id = ?", (trip_id,))
        trip_data["itinerary"] = [dict(row) for row in c.fetchall()]

        c.execute("SELECT id, amount, description FROM budget WHERE trip_id = ?", (trip_id,))
        trip_data["budget"] = [dict(row) for row in c.fetchall()]

        return jsonify(trip_data)
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>", methods=["PUT"])
@login_required
def update_trip(trip_id):
    user_id = g.user["id"]
    data = request.get_json()
    
    name = data.get("name", "").strip()
    start_date = data.get("start_date")
    end_date = data.get("end_date")
    
    if not name:
        return jsonify({"error": "Trip name is required"}), 400
    
    conn = get_db()
    try:
        # Check if trip exists and belongs to user
        trip = conn.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", 
                           (trip_id, user_id)).fetchone()
        if not trip:
            return jsonify({"error": "Trip not found or not authorized"}), 404
        
        # Update trip
        conn.execute("""
            UPDATE trips 
            SET name = ?, start_date = ?, end_date = ? 
            WHERE id = ? AND user_id = ?
        """, (name, start_date, end_date, trip_id, user_id))
        conn.commit()
        
        return jsonify({"message": "Trip updated successfully", "trip_id": trip_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>", methods=["DELETE"])
@login_required
def delete_trip(trip_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        # Check if trip exists and belongs to user
        trip = conn.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", 
                           (trip_id, user_id)).fetchone()
        if not trip:
            return jsonify({"error": "Trip not found or not authorized"}), 404
        
        # Delete trip (cascade will handle related records)
        conn.execute("DELETE FROM trips WHERE id = ? AND user_id = ?", (trip_id, user_id))
        conn.commit()
        
        return jsonify({"message": "Trip deleted successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

# --- data management for specific trips ---
# Notes
@app.route("/api/trips/<int:trip_id>/notes", methods=["POST"])
@login_required
def add_note(trip_id):
    data = request.get_json()
    content = data.get("content")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO notes (content, trip_id) VALUES (?, ?)", (content, trip_id))
        conn.commit()
        return jsonify({"id": c.lastrowid, "content": content}), 201
    finally:
        conn.close()

# Places
@app.route("/api/trips/<int:trip_id>/places", methods=["POST"])
@login_required
def add_place(trip_id):
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    name = data.get("name", "").strip()
    date = data.get("date")
    description = data.get("description", "").strip()
    user_id = g.user["id"]
    
    if not name:
        return jsonify({"error": "Place name is required"}), 400
    
    # Validate date format if provided
    if date:
        try:
            dt.datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user
        c.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", (trip_id, user_id))
        if not c.fetchone():
            return jsonify({"error": "Trip not found or not authorized"}), 404
        
        c.execute("INSERT INTO places (name, date, description, trip_id) VALUES (?, ?, ?, ?)", 
                  (name, date, description, trip_id))
        conn.commit()
        return jsonify({
            "id": c.lastrowid,
            "name": name,
            "date": date,
            "description": description,
            "message": "Place added successfully"
        }), 201
    except Exception as e:
        return jsonify({"error": "Failed to add place"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/places", methods=["GET"])
@login_required
def get_places(trip_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user
        c.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", (trip_id, user_id))
        if not c.fetchone():
            return jsonify({"error": "Trip not found or not authorized"}), 404
        
        c.execute("SELECT id, name, date, description FROM places WHERE trip_id = ? ORDER BY date ASC, id ASC", (trip_id,))
        places = c.fetchall()
        return jsonify({
            "places": [dict(place) for place in places],
            "count": len(places)
        })
    except Exception as e:
        return jsonify({"error": "Failed to fetch places"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/places/<int:place_id>", methods=["GET"])
@login_required
def get_place(trip_id, place_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user and place belongs to trip
        c.execute("""
            SELECT p.id, p.name, p.date, p.description 
            FROM places p 
            JOIN trips t ON p.trip_id = t.id 
            WHERE p.id = ? AND p.trip_id = ? AND t.user_id = ?
        """, (place_id, trip_id, user_id))
        place = c.fetchone()
        
        if not place:
            return jsonify({"error": "Place not found or not authorized"}), 404
        
        return jsonify(dict(place))
    except Exception as e:
        return jsonify({"error": "Failed to fetch place"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/places/<int:place_id>", methods=["PUT"])
@login_required
def update_place(trip_id, place_id):
    data = request.get_json()
    user_id = g.user["id"]
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    name = data.get("name", "").strip()
    date = data.get("date")
    description = data.get("description", "").strip()
    
    if not name:
        return jsonify({"error": "Place name is required"}), 400
    
    # Validate date format if provided
    if date:
        try:
            dt.datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user and place exists
        c.execute("""
            SELECT p.id FROM places p 
            JOIN trips t ON p.trip_id = t.id 
            WHERE p.id = ? AND p.trip_id = ? AND t.user_id = ?
        """, (place_id, trip_id, user_id))
        
        if not c.fetchone():
            return jsonify({"error": "Place not found or not authorized"}), 404
        
        c.execute("UPDATE places SET name = ?, date = ?, description = ? WHERE id = ?",
                  (name, date, description, place_id))
        conn.commit()
        
        if c.rowcount == 0:
            return jsonify({"error": "Failed to update place"}), 400
        
        return jsonify({
            "id": place_id,
            "name": name,
            "date": date,
            "description": description,
            "message": "Place updated successfully"
        })
    except Exception as e:
        return jsonify({"error": "Failed to update place"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/places/<int:place_id>", methods=["DELETE"])
@login_required
def delete_place(trip_id, place_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user and place exists
        c.execute("""
            SELECT p.id FROM places p 
            JOIN trips t ON p.trip_id = t.id 
            WHERE p.id = ? AND p.trip_id = ? AND t.user_id = ?
        """, (place_id, trip_id, user_id))
        
        if not c.fetchone():
            return jsonify({"error": "Place not found or not authorized"}), 404
        
        c.execute("DELETE FROM places WHERE id = ?", (place_id,))
        conn.commit()
        
        if c.rowcount == 0:
            return jsonify({"error": "Failed to delete place"}), 400
        
        return jsonify({"message": "Place deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to delete place"}), 500
    finally:
        conn.close()

# Itinerary
@app.route("/api/trips/<int:trip_id>/itinerary", methods=["POST"])
@login_required
def add_itinerary_item(trip_id):
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    name = data.get("name", "").strip()
    description = data.get("description", "").strip()
    date = data.get("date")
    user_id = g.user["id"]
    
    if not name:
        return jsonify({"error": "Itinerary item name is required"}), 400
    
    # Validate date format if provided
    if date:
        try:
            dt.datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user
        c.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", (trip_id, user_id))
        if not c.fetchone():
            return jsonify({"error": "Trip not found or not authorized"}), 404
        
        c.execute("INSERT INTO itinerary (name, description, date, trip_id) VALUES (?, ?, ?, ?)", 
                  (name, description, date, trip_id))
        conn.commit()
        return jsonify({
            "id": c.lastrowid,
            "name": name,
            "description": description,
            "date": date,
            "message": "Itinerary item added successfully"
        }), 201
    except Exception as e:
        return jsonify({"error": "Failed to add itinerary item"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/itinerary", methods=["GET"])
@login_required
def get_itinerary(trip_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user
        c.execute("SELECT id FROM trips WHERE id = ? AND user_id = ?", (trip_id, user_id))
        if not c.fetchone():
            return jsonify({"error": "Trip not found or not authorized"}), 404
        
        c.execute("SELECT id, name, description, date FROM itinerary WHERE trip_id = ? ORDER BY date ASC, id ASC", (trip_id,))
        itinerary_items = c.fetchall()
        return jsonify({
            "itinerary": [dict(item) for item in itinerary_items],
            "count": len(itinerary_items)
        })
    except Exception as e:
        return jsonify({"error": "Failed to fetch itinerary"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/itinerary/<int:itinerary_id>", methods=["GET"])
@login_required
def get_itinerary_item(trip_id, itinerary_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user and itinerary item belongs to trip
        c.execute("""
            SELECT i.id, i.name, i.description, i.date 
            FROM itinerary i 
            JOIN trips t ON i.trip_id = t.id 
            WHERE i.id = ? AND i.trip_id = ? AND t.user_id = ?
        """, (itinerary_id, trip_id, user_id))
        itinerary_item = c.fetchone()
        
        if not itinerary_item:
            return jsonify({"error": "Itinerary item not found or not authorized"}), 404
        
        return jsonify(dict(itinerary_item))
    except Exception as e:
        return jsonify({"error": "Failed to fetch itinerary item"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/itinerary/<int:itinerary_id>", methods=["PUT"])
@login_required
def update_itinerary_item(trip_id, itinerary_id):
    data = request.get_json()
    user_id = g.user["id"]
    
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    name = data.get("name", "").strip()
    description = data.get("description", "").strip()
    date = data.get("date")
    
    if not name:
        return jsonify({"error": "Itinerary item name is required"}), 400
    
    # Validate date format if provided
    if date:
        try:
            dt.datetime.strptime(date, "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user and itinerary item exists
        c.execute("""
            SELECT i.id FROM itinerary i 
            JOIN trips t ON i.trip_id = t.id 
            WHERE i.id = ? AND i.trip_id = ? AND t.user_id = ?
        """, (itinerary_id, trip_id, user_id))
        
        if not c.fetchone():
            return jsonify({"error": "Itinerary item not found or not authorized"}), 404
        
        c.execute("UPDATE itinerary SET name = ?, description = ?, date = ? WHERE id = ?",
                  (name, description, date, itinerary_id))
        conn.commit()
        
        if c.rowcount == 0:
            return jsonify({"error": "Failed to update itinerary item"}), 400
        
        return jsonify({
            "id": itinerary_id,
            "name": name,
            "description": description,
            "date": date,
            "message": "Itinerary item updated successfully"
        })
    except Exception as e:
        return jsonify({"error": "Failed to update itinerary item"}), 500
    finally:
        conn.close()

@app.route("/api/trips/<int:trip_id>/itinerary/<int:itinerary_id>", methods=["DELETE"])
@login_required
def delete_itinerary_item(trip_id, itinerary_id):
    user_id = g.user["id"]
    conn = get_db()
    try:
        c = conn.cursor()
        # Verify trip belongs to user and itinerary item exists
        c.execute("""
            SELECT i.id FROM itinerary i 
            JOIN trips t ON i.trip_id = t.id 
            WHERE i.id = ? AND i.trip_id = ? AND t.user_id = ?
        """, (itinerary_id, trip_id, user_id))
        
        if not c.fetchone():
            return jsonify({"error": "Itinerary item not found or not authorized"}), 404
        
        c.execute("DELETE FROM itinerary WHERE id = ?", (itinerary_id,))
        conn.commit()
        
        if c.rowcount == 0:
            return jsonify({"error": "Failed to delete itinerary item"}), 400
        
        return jsonify({"message": "Itinerary item deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": "Failed to delete itinerary item"}), 500
    finally:
        conn.close()

# Budget
@app.route("/api/trips/<int:trip_id>/budget", methods=["POST"])
@login_required
def add_budget_item(trip_id):
    data = request.get_json()
    amount = data.get("amount")
    description = data.get("description")
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("INSERT INTO budget (amount, description, trip_id) VALUES (?, ?, ?)", (amount, description, trip_id))
        conn.commit()
        return jsonify({"id": c.lastrowid, "amount": amount, "description": description}), 201
    finally:
        conn.close()

@app.route("/api/health")
def health():
    return {"status": "ok"}

# --- Swagger Documentation Routes ---
@app.route("/docs")
def swagger_ui():
    """Serve Swagger UI documentation"""
    return send_from_directory('.', 'swagger-ui.html')

@app.route("/swagger.yaml")
def swagger_spec():
    """Serve Swagger YAML specification"""
    return send_from_directory('.', 'swagger.yaml')

@app.route("/")
def index():
    """API documentation home page"""
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Travel Trip Management API</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #1b5e20; margin-bottom: 20px; }
            .btn { display: inline-block; padding: 12px 24px; background: #2e7d32; color: white; text-decoration: none; border-radius: 4px; margin: 10px 5px; }
            .btn:hover { background: #1b5e20; }
            .endpoint { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #2e7d32; }
            .method { font-weight: bold; color: #1b5e20; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧳 Travel Trip Management API</h1>
            <p>Welcome to the Travel Trip Management API! This API provides comprehensive trip management functionality.</p>
            
            <h2>📚 Documentation</h2>
            <a href="/docs" class="btn">📖 View Interactive API Docs (Swagger UI)</a>
            <a href="/swagger.yaml" class="btn">📄 Download OpenAPI Spec</a>
            
            <h2>🚀 Quick Start</h2>
            <div class="endpoint">
                <div class="method">POST</div> /api/register - Register new user
            </div>
            <div class="endpoint">
                <div class="method">POST</div> /api/login - Login user
            </div>
            <div class="endpoint">
                <div class="method">GET</div> /api/trips - Get all trips
            </div>
            <div class="endpoint">
                <div class="method">POST</div> /api/trips - Create new trip
            </div>
            
            <h2>🔧 Base URL</h2>
            <p><code>{{ request.url_root }}api/</code></p>
            
            <h2>🔐 Authentication</h2>
            <p>Use JWT tokens in Authorization header: <code>Bearer &lt;token&gt;</code></p>
            
            <p><em>Click "View Interactive API Docs" above to explore all endpoints with examples!</em></p>
        </div>
    </body>
    </html>
    """)

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
