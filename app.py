import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from datetime import datetime, timedelta
import bcrypt, uuid
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 유저 테이블 생성
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_admin INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                status_updated_at TEXT,
                bank_name TEXT,
                account_number TEXT,
                account_holder TEXT
            )
        ''')

        # 관리자 계정이 없는 경우, 자동 생성
        cursor.execute("SELECT * FROM user WHERE is_admin = 1")
        if cursor.fetchone() is None:
            admin_id = str(uuid.uuid4())
            username = "admin"
            raw_pw = "admin123"
            hashed_pw = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt())

            cursor.execute("""
                INSERT INTO user (id, username, password, is_admin)
                VALUES (?, ?, ?, 1)
            """, (admin_id, username, hashed_pw))
            print("최초 관리자 계정 생성됨 → admin / admin123")

        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL,
                image_path TEXT
            )
        """)
        # 신고 테이블 생성
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL CHECK (target_type IN ('user', 'product')),
                reason TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (reporter_id) REFERENCES user(id)
            )
        ''')
        # 채팅 메시지 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_message (
                id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT,
                is_read INTEGER DEFAULT 0,
                type TEXT DEFAULT 'user'
            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']

        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))

        user_id = str(uuid.uuid4())
        hashed_pw = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt())

        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, hashed_pw))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        raw_pw = request.form['password']

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(raw_pw.encode(), user['password']):
            status = user['status']
            status_time = user['status_updated_at']
            
            # 휴면 자동 복구 검사
            if status == 'dormant' and status_time:
                dormant_since = datetime.fromisoformat(status_time)
                days_passed = (datetime.now() - dormant_since).days
                days_remaining = max(0, 90 - days_passed)

                if days_remaining == 0:
                    # 자동 복구 처리
                    cursor.execute("UPDATE user SET status = 'active', status_updated_at = NULL WHERE id = ?", (user['id'],))
                    db.commit()
                    status = 'active'
                else:
                    flash(f"❌ 이 계정은 휴면 상태입니다. {days_remaining}일 후 자동 해제됩니다.")
                    return redirect(url_for('login'))

            elif status == 'banned':
                flash("이 계정은 영구 정지되었습니다.")
                return redirect(url_for('login'))

            # 로그인 성공
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()

    # 현재 사용자
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 전체 상품
    cursor.execute("""
        SELECT p.*, u.username
        FROM product p
        JOIN user u ON p.seller_id = u.id
        ORDER BY p.title
    """)
    all_products = cursor.fetchall()

    # 내 상품
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    my_products = cursor.fetchall()

    return render_template('dashboard.html', all_products=all_products, my_products=my_products, user=current_user)

# 사용자 페이지 조회
@app.route('/user/<user_id>')
def view_user(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT id, username, bio, status, status_updated_at
        FROM user
        WHERE id = ?
    """, (user_id,))
    user = cursor.fetchone()
    if not user:
        flash('사용자를 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    return render_template('user_profile.html', user=user)

# 프로필 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        # 소개글, 계좌 정보 업데이트
        bio = request.form.get('bio', '')
        bank_name = request.form.get('bank_name', '')
        account_number = request.form.get('account_number', '')
        account_holder = request.form.get('account_holder', '')

        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if account_number and not account_number.isdigit():
            flash("계좌번호는 숫자만 입력해주세요.")
            return redirect(url_for('profile'))

        cursor.execute('''
            UPDATE user
            SET bio = ?, bank_name = ?, account_number = ?, account_holder = ?
            WHERE id = ?
        ''', (bio, bank_name, account_number, account_holder, session['user_id']))

        # 비밀번호 변경 요청 처리
        if current_password or new_password or confirm_password:
            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            user = cursor.fetchone()

            if not user or not bcrypt.checkpw(current_password.encode(), user['password']):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))

            if new_password != confirm_password:
                flash('새 비밀번호와 확인이 일치하지 않습니다.')
                return redirect(url_for('profile'))

            new_hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_hashed, session['user_id']))
            flash('비밀번호가 성공적으로 변경되었습니다.')

        db.commit()
        flash('프로필이 업데이트되었습니다.')
        return redirect(url_for('profile'))

    # 사용자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    return render_template('profile.html', user=current_user)

# 상품 등록
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        image = request.files['image']
        image_path = None

        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(save_path)
            image_path = f"uploads/{filename}" 

        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO product (id, title, description, price, seller_id, image_path)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (product_id, title, description, price, session['user_id'], image_path))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()

    # 상품 조회
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    # 판매자 정보 조회 
    cursor.execute("SELECT id, username FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()

    return render_template('view_product.html', product=product, seller=seller)

# 상품 수정
@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    # 상품이 없거나 등록자가 아닌 경우 접근 차단
    if not product:
        flash("상품을 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))
    if product['seller_id'] != session['user_id']:
        flash("상품을 수정할 수 있는 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        cursor.execute("""
            UPDATE product SET title = ?, description = ?, price = ? WHERE id = ?
        """, (title, description, price, product_id))
        db.commit()
        flash("상품이 수정되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))

    return render_template('edit_product.html', product=product)

# 상품 삭제
@app.route('/delete_product/<product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # 권한 확인
    db = get_db()
    cursor = db.cursor()

    # 현재 로그인 유저가 관리자이거나, 상품 등록자일 경우에만 삭제 가능
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash("상품이 존재하지 않습니다.")
        return redirect(url_for('dashboard'))

    if session.get('is_admin') == 1 or session['user_id'] == product['seller_id']:
        cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
        db.commit()
        flash("상품이 삭제되었습니다.")
    else:
        flash("상품을 삭제할 권한이 없습니다.")

    return redirect(url_for('dashboard'))  # or redirect back

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        target_type = request.form['target_type']
        target_id = request.form['target_id']
        reason = request.form['reason']

        db = get_db()
        cursor = db.cursor()

        if target_type == 'user':
            # 사용자명으로 ID 조회
            cursor.execute("SELECT id FROM user WHERE username = ?", (target_id,))
            result = cursor.fetchone()
            if not result:
                flash("존재하지 않는 사용자입니다.")
                return redirect(url_for('report'))
            real_target_id = result['id']

            # 자기 자신 신고 방지
            if session['user_id'] == real_target_id:
                flash("자기 자신은 신고할 수 없습니다.")
                return redirect(url_for('report'))

        elif target_type == 'product':
            # 상품 ID로 조회
            cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
            result = cursor.fetchone()
            if not result:
                flash("존재하지 않는 상품입니다.")
                return redirect(url_for('report'))

            # 자기가 등록한 상품 신고 방지
            if result['seller_id'] == session['user_id']:
                flash("자신이 등록한 상품은 신고할 수 없습니다.")
                return redirect(url_for('report'))

            real_target_id = result['id']

        # 신고 등록
        report_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()

        cursor.execute('''
            INSERT INTO report (id, reporter_id, target_id, target_type, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (report_id, session['user_id'], real_target_id, target_type, reason, created_at))

        db.commit()

        if target_type == 'user':
            cursor.execute("SELECT COUNT(*) FROM report WHERE target_id = ? AND target_type = 'user'", (real_target_id,))
            count = cursor.fetchone()[0]
            if count >= 10:
                cursor.execute("UPDATE user SET status = 'dormant', status_updated_at = ? WHERE id = ?",
                            (datetime.now().isoformat(), real_target_id))
                db.commit()
                flash("⚠️ 해당 사용자가 누적 신고로 휴면 처리되었습니다.")

        elif target_type == 'product':
            cursor.execute("SELECT COUNT(*) FROM report WHERE target_id = ? AND target_type = 'product'", (real_target_id,))
            count = cursor.fetchone()[0]
            if count >= 10:
                cursor.execute("DELETE FROM product WHERE id = ?", (real_target_id,))
                db.commit()
                flash("⚠️ 해당 상품은 누적 신고로 삭제되었습니다.")

        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# [관리자] 신고 처리 
@app.route('/admin/reports')
def admin_view_reports():
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash("관리자만 접근할 수 있습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    # 전체 신고 내역 + 신고자 이름 가져오기
    cursor.execute('''
        SELECT r.*, u1.username AS reporter_name
        FROM report r
        LEFT JOIN user u1 ON r.reporter_id = u1.id
        ORDER BY r.created_at DESC
    ''')
    raw_reports = cursor.fetchall()

    reports = []
    for r in raw_reports:
        # 이름 조회
        if r['target_type'] == 'user':
            cursor.execute("SELECT username, status FROM user WHERE id = ?", (r['target_id'],))
            result = cursor.fetchone()
            if result:
                target_name = result['username']
                status = result['status']
                if status == 'dormant':
                    target_status = '휴면 상태'
                elif status == 'banned':
                    target_status = '영구 정지'
                else:
                    target_status = '활성'
            else:
                target_name = "(알 수 없음)"
                target_status = '탈퇴됨'

        elif r['target_type'] == 'product':
            cursor.execute("SELECT title FROM product WHERE id = ?", (r['target_id'],))
            result = cursor.fetchone()
            if result:
                target_name = result['title']
                target_status = ''  # 상품은 삭제 여부만 판단
            else:
                target_name = "(삭제된 상품)"
                target_status = '삭제됨'

        # 신고 누적 횟수 조회
        cursor.execute('''
            SELECT COUNT(*) FROM report
            WHERE target_id = ? AND target_type = ?
        ''', (r['target_id'], r['target_type']))
        count = cursor.fetchone()[0]

        r = dict(r)
        r['target_name'] = target_name
        r['target_status'] = target_status  # 👈 상태 필드 추가
        r['report_count'] = count
        reports.append(r)

    return render_template('admin_reports.html', reports=reports)

# [관리자] 신고자 휴면/정지 처리
@app.route('/admin/user_action/<user_id>/<action>', methods=['POST'])
def admin_user_action(user_id, action):
    if 'user_id' not in session or session.get('is_admin') != 1:
        abort(403)

    db = get_db()
    cursor = db.cursor()

    if action == 'dormant':
        status = 'dormant'
    elif action == 'banned':
        status = 'banned'
    else:
        flash("잘못된 요청입니다.")
        return redirect(url_for('admin_view_reports'))

    cursor.execute("UPDATE user SET status = ?, status_updated_at = ? WHERE id = ?", 
                   (status, datetime.now().isoformat(), user_id))
    db.commit()
    flash(f"사용자에게 '{status}' 상태 적용 완료")
    return redirect(url_for('admin_view_reports'))
# [관리자] 신고 상품 삭제 처리
@app.route('/admin/delete_product/<product_id>', methods=['POST'])
def admin_delete_product(product_id):
    if 'user_id' not in session or session.get('is_admin') != 1:
        abort(403)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    flash("🗑️ 상품이 삭제되었습니다.")
    return redirect(url_for('admin_view_reports'))

# [관리자] 사용자 페이지에서 유저 상태 처리 (휴면/복구/정지)
@app.route('/set_user_status/<user_id>/<status>', methods=['POST'])
def set_user_status(user_id, status):
    if 'user_id' not in session or session.get('is_admin') != 1:
        flash("권한이 없습니다.")
        return redirect(url_for('dashboard'))

    if status not in ['active', 'dormant', 'banned']:
        flash("잘못된 상태입니다.")
        return redirect(url_for('user_profile', user_id=user_id))

    db = get_db()
    cursor = db.cursor()
    timestamp = datetime.now().isoformat() if status != 'active' else None

    cursor.execute("""
        UPDATE user SET status = ?, status_updated_at = ? WHERE id = ?
    """, (status, timestamp, user_id))
    db.commit()

    flash(f"사용자 상태가 '{status}'로 변경되었습니다.")
    return redirect(url_for('view_user', user_id=user_id))

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    db = get_db()
    cursor = db.cursor()

    timestamp = datetime.now().isoformat()

    # 채팅 메시지 저장
    cursor.execute("""
        INSERT INTO chat_message (id, sender_id, receiver_id, message, timestamp, is_read, type)
        VALUES (?, ?, ?, ?, ?, 0, 'public')
    """, (
        data['message_id'],
        session['user_id'],  # 보낸 사람 ID
        'public',            # 모든 사용자에게 공개되는 메시지
        data['message'],
        timestamp
    ))
    db.commit()

    send({
        'username': data['username'],
        'message': data['message'],
        'timestamp': timestamp
    }, broadcast=True)

# 로그에 남아있던 실시간 메시지 불러오기
@app.route('/load_public_messages')
def load_public_messages():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT m.message, m.timestamp, u.username
        FROM chat_message m
        JOIN user u ON m.sender_id = u.id
        WHERE m.receiver_id = 'public'
        ORDER BY m.timestamp ASC
    """)
    messages = []
    for row in cursor.fetchall():
        messages.append({
            'username': row['username'],
            'message': row['message'],
            'timestamp': row['timestamp']  # ⬅️ 여기: ISO 문자열 그대로 넘겨줌
        })
    return jsonify({'messages': messages})

# 서버 시작 시 실시간 메시지 삭제할 함수
def delete_old_chat_messages():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        DELETE FROM chat_message
        WHERE receiver_id = 'public'
    """)
    db.commit()

# 1대1 채팅 전: 채팅 방 ID 생성 함수 추가 
def get_private_room(user1, user2):
    return '_'.join(sorted([user1, user2]))

# 1대1 채팅
@app.route('/chat/<user_id>')
def private_chat(user_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if user_id == session['user_id']:
        flash("자기 자신과는 채팅할 수 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    # 채팅 상대 존재 여부 확인
    cursor.execute("SELECT username FROM user WHERE id = ?", (user_id,))
    target_user = cursor.fetchone()
    if not target_user:
        flash("사용자를 찾을 수 없습니다.")
        return redirect(url_for('dashboard'))
    
    # 읽음 처리 쿼리 추가
    cursor.execute("""
        UPDATE chat_message
        SET is_read = 1
        WHERE receiver_id = ? AND sender_id = ?
    """, (session['user_id'], user_id))
    db.commit()

    # 시스템 메시지: 상품 기반 안내 메시지
    product_id = request.args.get("product_id")
    if product_id:
        # 이미 안내 메시지가 존재하는지 확인
        cursor.execute("""
            SELECT * FROM chat_message
            WHERE sender_id = ? AND receiver_id = ? AND type = 'system'
              AND message LIKE ?
        """, (session['user_id'], user_id, "%상품에 대한 거래입니다.%"))
        existing_msg = cursor.fetchone()

        if not existing_msg:
            cursor.execute("SELECT title FROM product WHERE id = ?", (product_id,))
            product = cursor.fetchone()
            if product:
                info_msg = f"[{product['title']}] 상품에 대한 거래입니다."
                timestamp = datetime.now().isoformat()
                msg_id = str(uuid.uuid4())

                cursor.execute("""
                    INSERT INTO chat_message (id, sender_id, receiver_id, message, timestamp, is_read, type)
                    VALUES (?, ?, ?, ?, ?, 0, 'system')
                """, (msg_id, session['user_id'], user_id, info_msg, timestamp))
                db.commit()

    # 채팅 기록 불러오기
    room_id = get_private_room(session['user_id'], user_id)
    cursor.execute("""
        SELECT * FROM chat_message
        WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ORDER BY timestamp ASC
    """, (session['user_id'], user_id, user_id, session['user_id']))
    chat_history = cursor.fetchall()

    return render_template('private_chat.html',
                           target_id=user_id,
                           target_username=target_user['username'],
                           chat_history=chat_history,
                           my_id=session['user_id'])

# SocketIO 채널 확장
@socketio.on('join_room')
def handle_join(data):
    room = get_private_room(data['sender_id'], data['receiver_id'])
    join_room(room)

@socketio.on('private_message')
def handle_private_message(data):
    room = get_private_room(data['sender_id'], data['receiver_id'])
    message_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()  # 예: 2025-04-25 13:45:22

    # DB 저장
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO chat_message (id, sender_id, receiver_id, message, timestamp, is_read)
        VALUES (?, ?, ?, ?, ?, 0)
    """, (message_id, data['sender_id'], data['receiver_id'], data['message'], timestamp))
    db.commit()

    # timestamp 포함해서 전송
    data['timestamp'] = timestamp
    emit('new_private_message', data, room=room)

# 메시지 열람 기능
@app.route('/messages')
def message_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 상대방 목록과 읽지 않은 메시지 존재 여부까지 함께 가져오기
    cursor.execute("""
        SELECT DISTINCT
            u.id AS chat_partner_id,
            u.username AS chat_partner_name,
            EXISTS (
                SELECT 1 FROM chat_message m2
                WHERE m2.sender_id = u.id AND m2.receiver_id = ?
                AND m2.is_read = 0
            ) AS has_unread
        FROM chat_message m
        JOIN user u ON u.id = CASE
            WHEN m.sender_id = ? THEN m.receiver_id
            ELSE m.sender_id
        END
        WHERE (m.sender_id = ? OR m.receiver_id = ?)
          AND u.id != ?
    """, (session['user_id'], session['user_id'], session['user_id'], session['user_id'], session['user_id']))

    chat_partners = cursor.fetchall()

    return render_template('message_list.html', partners=chat_partners)

# 안 읽은 대화 상대 세는 함수
def get_unread_partner_count(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT COUNT(DISTINCT sender_id)
        FROM chat_message
        WHERE receiver_id = ? AND is_read = 0
          AND sender_id != ?
    """, (user_id, user_id))  # 자기 자신이 보낸 메시지는 제외
    result = cursor.fetchone()
    return result[0] if result else 0

# 안 읽은 대화 상대 수 모든 페이지에 전달 
@app.before_request
def inject_unread_count():
    if 'user_id' in session:
        g.unread_count = get_unread_partner_count(session['user_id'])
    else:
        g.unread_count = 0

# 계좌 정보를 가져오기 -> 이후 계좌번호 원클릭 전송
@app.route('/get_account_info')
def get_account_info():
    if 'user_id' not in session:
        return jsonify({'error': '로그인 필요'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT bank_name, account_number, account_holder FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()

    if user and user['bank_name'] and user['account_number'] and user['account_holder']:
        holder = user['account_holder']
        # 이름 마스킹
        if len(holder) == 2:
            masked = holder[0] + 'O'
        elif len(holder) >= 3:
            masked = holder[0] + 'O'*(len(holder)-2) + holder[-1]
        else:
            masked = holder

        msg = f"📎 {masked}\n   {user['bank_name']} {user['account_number']}"
        return jsonify({'account_info': msg})
    else:
        return jsonify({'account_info': None})

# 상품 검색
@app.route('/search')
def search():
    query = request.args.get('q', '').strip()

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT * FROM product
        WHERE title LIKE ?
        ORDER BY title ASC
    """, (f'%{query}%',))
    results = cursor.fetchall()

    return render_template('search_results.html', query=query, results=results)


if __name__ == '__main__':
    with app.app_context():
        init_db()
        delete_old_chat_messages() # 서버 시작 시 기존 DB에 저장되었던 실시간 메시지 삭제 
    socketio.run(app, debug=True)
