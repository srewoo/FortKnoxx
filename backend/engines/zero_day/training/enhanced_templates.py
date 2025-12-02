"""
Enhanced Vulnerability Templates for GNN Training
More diverse and realistic vulnerability patterns across multiple languages
"""

# Expanded vulnerability templates with multiple languages and patterns
ENHANCED_TEMPLATES = {
    "sql_injection": [
        # Python examples
        '''
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
''',
        '''
def search_users(name):
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    return db.execute(query)
''',
        '''
def update_profile(user_id, bio):
    cursor.execute("UPDATE profiles SET bio='" + bio + "' WHERE user_id=" + str(user_id))
''',
        # JavaScript examples
        '''
function getUser(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.query(query);
}
''',
        '''
const searchProducts = (term) => {
    return db.query(`SELECT * FROM products WHERE name LIKE '%${term}%'`);
};
''',
    ],

    "command_injection": [
        '''
import os
def run_command(cmd):
    os.system(cmd)
''',
        '''
import subprocess
def execute(user_input):
    subprocess.call(user_input, shell=True)
''',
        '''
def ping_host(hostname):
    os.popen(f"ping -c 1 {hostname}").read()
''',
        '''
function execCommand(cmd) {
    require('child_process').exec(cmd, (error, stdout) => {
        console.log(stdout);
    });
}
''',
    ],

    "path_traversal": [
        '''
def read_file(filename):
    with open("/data/" + filename) as f:
        return f.read()
''',
        '''
def serve_file(path):
    return send_file(os.path.join(UPLOAD_DIR, path))
''',
        '''
def download_report(filename):
    file_path = "./reports/" + filename
    return open(file_path, 'rb').read()
''',
    ],

    "xss": [
        '''
def render_page(user_content):
    return f"<html><body>{user_content}</body></html>"
''',
        '''
function displayComment(comment) {
    document.getElementById('comments').innerHTML += comment;
}
''',
        '''
def show_message(msg):
    return render_template_string(f"<p>{msg}</p>")
''',
    ],

    "unsafe_deserialization": [
        '''
import pickle
def load_data(data):
    return pickle.loads(data)
''',
        '''
def deserialize(data):
    return eval(data)
''',
        '''
import yaml
def load_config(config_str):
    return yaml.load(config_str)  # Should use safe_load
''',
    ],

    "weak_crypto": [
        '''
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
''',
        '''
def encrypt_data(data):
    import hashlib
    return hashlib.sha1(data.encode()).hexdigest()
''',
        '''
from Crypto.Cipher import DES
def weak_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)
''',
    ],

    "hardcoded_secrets": [
        '''
API_KEY = "sk-1234567890abcdef"
def authenticate():
    return API_KEY
''',
        '''
DATABASE_PASSWORD = "admin123"
def connect_db():
    return psycopg2.connect(password=DATABASE_PASSWORD)
''',
        '''
const AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
function uploadToS3() {
    return new AWS.S3({secretAccessKey: AWS_SECRET});
}
''',
    ],

    "insecure_random": [
        '''
import random
def generate_token():
    return ''.join(random.choice('0123456789abcdef') for _ in range(32))
''',
        '''
function generateSessionId() {
    return Math.random().toString(36).substring(7);
}
''',
    ],

    "xxe": [
        '''
import xml.etree.ElementTree as ET
def parse_xml(xml_string):
    return ET.fromstring(xml_string)  # Vulnerable to XXE
''',
        '''
from lxml import etree
def process_xml(data):
    parser = etree.XMLParser()
    return etree.fromstring(data, parser)
''',
    ],

    "ssrf": [
        '''
import requests
def fetch_url(url):
    return requests.get(url).text
''',
        '''
def proxy_request(target_url):
    response = urllib.request.urlopen(target_url)
    return response.read()
''',
    ],

    "ldap_injection": [
        '''
def search_user(username):
    filter_str = f"(uid={username})"
    return ldap.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
''',
    ],

    "code_injection": [
        '''
def execute_code(code_str):
    exec(code_str)
''',
        '''
function evalUserCode(code) {
    return eval(code);
}
''',
    ],

    "authentication_bypass": [
        '''
def login(username, password):
    if password == "":
        return True
    return check_credentials(username, password)
''',
        '''
def authenticate(token):
    if token:
        return True  # No validation
''',
    ],

    "authorization_bypass": [
        '''
def delete_user(user_id):
    # No check if current user can delete this user
    User.objects.filter(id=user_id).delete()
''',
        '''
function updateProfile(userId, data) {
    // No ownership check
    db.users.update({id: userId}, data);
}
''',
    ],

    "csrf": [
        '''
@app.route('/transfer', methods=['POST'])
def transfer_money():
    # No CSRF token check
    amount = request.form['amount']
    recipient = request.form['recipient']
    transfer(amount, recipient)
''',
    ],

    "open_redirect": [
        '''
def redirect_user(url):
    return redirect(url)  # No validation
''',
        '''
function goToUrl(destination) {
    window.location = destination;  // Unvalidated
}
''',
    ],

    "race_condition": [
        '''
def withdraw(account_id, amount):
    balance = get_balance(account_id)
    if balance >= amount:
        # Race condition here
        time.sleep(0.1)
        update_balance(account_id, balance - amount)
''',
    ],

    "resource_exhaustion": [
        '''
def process_file(filename):
    with open(filename, 'r') as f:
        return f.read()  # No size limit
''',
        '''
function processImage(imageData) {
    // No size validation
    return sharp(imageData).resize(10000, 10000).toBuffer();
}
''',
    ],

    "memory_leak": [
        '''
cache = {}
def store_data(key, value):
    cache[key] = value  # Never cleared
''',
    ],

    "sensitive_data_exposure": [
        '''
def get_user_details(user_id):
    user = User.query.get(user_id)
    return jsonify({
        'id': user.id,
        'email': user.email,
        'password': user.password,  # Exposed!
        'ssn': user.ssn
    })
''',
    ],

    "null_pointer_dereference": [
        '''
def process_user(user_id):
    user = find_user(user_id)  # May return None
    return user.name  # No null check
''',
    ],

    "buffer_overflow": [
        '''
void copy_data(char *input) {
    char buffer[10];
    strcpy(buffer, input);  // No bounds check
}
''',
    ],

    "use_after_free": [
        '''
void process() {
    char *ptr = malloc(100);
    free(ptr);
    strcpy(ptr, "data");  // Use after free
}
''',
    ],

    "session_fixation": [
        '''
def login(username, password):
    if check_credentials(username, password):
        # Session ID not regenerated
        session['user'] = username
''',
    ],
}


def get_all_templates():
    """Get all vulnerability templates"""
    return ENHANCED_TEMPLATES


def get_template_count():
    """Get count of templates per vulnerability type"""
    return {vuln_type: len(templates) for vuln_type, templates in ENHANCED_TEMPLATES.items()}
