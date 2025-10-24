import os
import shutil
import zipfile
import rarfile
import datetime
import patoolib
import magic
import pyclamd
import traceback
import subprocess
import logging
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
from patoolib.util import PatoolError
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import cast, Integer
import threading
from prometheus_client import start_http_server, Gauge
import prometheus_client
import requests
import socket
import random
import string
import py7zr

# Настройка логирования
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Настройки
CLAMD_HOST = os.getenv('CLAMD_HOST')
CLAMD_PORT = int(os.getenv('CLAMD_PORT'))
UPLOAD_FOLDER = "/tmp/uploads"
DATABASE_URI = os.getenv("DATABASE_URI")

clamav_status_metric = Gauge('clamav_status_metric', 'Clamav connection status', ['host'])
clamav_requests_metric = Gauge('clamav_requests_metric', 'Количество проверенных файлов', ['token'])
clamav_requests_count_metric = Gauge('clamav_requests_count_metric', 'Количество запросов', ['token'])
prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)

host_name = os.getenv("HOSTNAME", "unknown")

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class ApiToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(hours=3))
    token = db.Column(db.String(64), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    result = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255), nullable=True)

    def __init__(self, token, filename, result, description):
        self.token = token
        self.filename = filename
        self.result = result
        self.description = description

with app.app_context():
    db.create_all()

def generate_unique_id(length=12):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choices(chars, k=length))

logger.info(f"Generated unique ID: {generate_unique_id(12)}")

def get_clamav_client():
    try:
        client = pyclamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT)
        client.ping()
        clamav_status_metric.labels(host=host_name).set(1)
        return client
    except Exception as e:
        logger.error(f"Ошибка подключения к ClamD: {e}")
        clamav_status_metric.labels(host=host_name).set(0)
        return None

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def is_archive(file_path):
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)
    logger.debug(f"MIME-тип файла {file_path}: {mime_type}")
    return mime_type in [
        "application/zip", "application/x-tar", "application/x-7z-compressed",
        "application/x-rar", "application/gzip", "application/x-bzip2"
    ]

#def is_password_protected(file_path):
#    try:
#        with zipfile.ZipFile(file_path) as z:
#            for file in z.infolist():
#                if file.flag_bits & 0x1:
#                    logger.warning(f"Архив {file_path} запаролен!")
#                    return True
#        return False
#    except zipfile.BadZipFile:
#        logger.error(f"Ошибка формата архива {file_path}")
#        return False
#    except Exception as e:
#        logger.error(f"Ошибка при проверке пароля: {e}")
#        return False

def is_password_protected(file_path):
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file_path)
    logger.debug(f"MIME type of file {file_path}: {mime_type}")

    if mime_type == "application/zip":
        try:
            with zipfile.ZipFile(file_path) as z:
                for file in z.infolist():
                    if file.flag_bits & 0x1:
                        logger.warning(f"Архив {file_path} запаролен!")
                        return True
            return False
        except zipfile.BadZipFile:
            logger.error(f"Ошибка формата архива {file_path}")
            return False
        except Exception as e:
            logger.error(f"Ошибка при проверке пароля: {e}")
            return False
    elif mime_type == "application/x-7z-compressed":
        try:
            result = subprocess.run(
                ["/usr/bin/7z", "t", file_path],
                capture_output=True,
                text=True
            )
            if "password" in result.stderr.lower() or result.returncode == 2:
                logger.warning(f"Архив {file_path} запаролен!")
                return True
            logger.debug(f"7z test output: {result.stderr}")
            return False
        except Exception as e:
            logger.error(f"Ошибка при проверке пароля 7z: {e}")
            return True
    elif mime_type == "application/x-rar":
        try:
            with rarfile.RarFile(file_path) as r:
                for file in r.infolist():
                    if file.needs_password():
                        logger.warning(f"Архив {file_path} запаролен!")
                        return True
            return False
        except rarfile.BadRarFile:
            logger.error(f"Ошибка RAR формата архива: {file_path}")
            return False
        except Exception as e:
            logger.error(f"Ошибка при проверке пароля RAR: {e}")
            return False
    else:
        # Для других архивов
        return False

def extract_archive_recursive(archive_path, extract_folder, depth=0, max_depth=5):
    if depth > max_depth:
        logger.warning(f"Превышена максимальная глубина вложенности ({max_depth}) для {archive_path}")
        return "ERROR: Max recursion depth exceeded", {"status": "ERROR", "error": "Max recursion depth exceeded"}, []

    os.makedirs(extract_folder, exist_ok=True)
    archive_structure = {"status": "CLEAN", "contents": {}}
    extracted_files_list = []

    if is_password_protected(archive_path):
        logger.warning(f"Архив {archive_path} защищен паролем")
        archive_structure["status"] = "PASSWORD_PROTECTED"
        return "PASSWORD_PROTECTED", archive_structure, [(archive_path, os.path.basename(archive_path), None)]

    try:
        logger.info(f"Распаковка {archive_path} в {extract_folder} (глубина: {depth})...")
        patoolib.extract_archive(archive_path, outdir=extract_folder, verbosity=3)
        extracted_files = list(os.scandir(extract_folder))

        if not extracted_files:
            logger.warning(f"Архив {archive_path} пустой или не распакован")
            return True, archive_structure, [(archive_path, os.path.basename(archive_path), None)]

        clamav = get_clamav_client()
        if clamav is None:
            raise Exception("ClamAV not available during extraction")

        for item in extracted_files:
            item_name = os.path.basename(item.path)
            if item.is_file():
                if is_archive(item.path):
                    sub_extract_folder = f"{item.path}_extracted"
                    result, sub_structure, sub_files = extract_archive_recursive(item.path, sub_extract_folder, depth + 1, max_depth)
                    archive_structure["contents"][item_name] = sub_structure
                    extracted_files_list.extend(sub_files)
                    if isinstance(sub_structure["status"], (list, tuple)) and sub_structure["status"][0] == "FOUND":
                        archive_structure["status"] = ["FOUND", "Nested archive contains threats"]
                    elif sub_structure["status"] == "PASSWORD_PROTECTED":
                        archive_structure["contents"][item_name]["status"] = "PASSWORD_PROTECTED"
                    elif isinstance(sub_structure["status"], str) and sub_structure["status"].startswith("ERROR"):
                        archive_structure["contents"][item_name]["status"] = "ERROR"
                else:
                    with open(item.path, "rb") as f:
                        result = clamav.scan_stream(f.read())
                        scan_result = result["stream"] if result else "CLEAN"
                        archive_structure["contents"][item_name] = {"status": scan_result}
                        if scan_result != "CLEAN":
                            archive_structure["status"] = scan_result
                    extracted_files_list.append((item.path, item_name, archive_path))

        logger.debug(f"archive_structure после обработки {archive_path}: {archive_structure}")
        return True, archive_structure, extracted_files_list
    except PatoolError as e:
        logger.error(f"Ошибка при извлечении архива {archive_path}: {str(e)}")
        archive_structure["status"] = "ERROR"
        archive_structure["error"] = str(e)
        return f"ERROR: {str(e)}", archive_structure, [(archive_path, os.path.basename(archive_path), None)]
    except Exception as e:
        logger.error(f"Неизвестная ошибка при распаковке {archive_path}: {e}")
        archive_structure["status"] = "ERROR"
        archive_structure["error"] = str(e)
        return f"ERROR: {str(e)}", archive_structure, [(archive_path, os.path.basename(archive_path), None)]

@app.route("/scan", methods=["POST"])
def scan_file():
    clamav = get_clamav_client()
    if clamav is None:
        return jsonify({"error": "ClamAV is not available"}), 500

    if "file" not in request.files:
        return jsonify({"error": "File not found in request"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "File name is empty"}), 400

    token_header = request.headers.get("Authorization")
    if not token_header:
        return jsonify({"error": "Authorization header is required"}), 401

    parts = token_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return jsonify({"error": "Invalid Authorization header format"}), 401

    token = parts[1]
    token_entry = ApiToken.query.filter_by(token=token).first()
    if not token_entry:
        return jsonify({"error": "token forbidden"}), 403

    token_desc = token_entry.description if token_entry.description else "unknown"

    unique_folder = os.path.join(app.config["UPLOAD_FOLDER"], generate_unique_id(16))
    os.makedirs(unique_folder, exist_ok=True)

    filename = secure_filename(file.filename)
    file_path = os.path.join(unique_folder, filename)
    file.save(file_path)

    if os.path.getsize(file_path) > 100 * 1024 * 1024:
        shutil.rmtree(unique_folder)
        return jsonify({"error": "File size is more than 100MB"}), 400

    scan_results = {}
    extracted_files = []

    try:
        if is_archive(file_path):
            extract_folder = os.path.join(unique_folder, "extracted")
            extraction_result, archive_structure, extracted_files = extract_archive_recursive(file_path, extract_folder)

            if extraction_result == "PASSWORD_PROTECTED":
                scan_results[filename] = {"status": "PASSWORD_PROTECTED"}
                shutil.rmtree(unique_folder)
                return jsonify({"warning": "The archive is password protected. Files cannot be verified.", filename: {"status": "PASSWORD_PROTECTED"}}), 400
            elif isinstance(extraction_result, str) and extraction_result.startswith("ERROR"):
                logger.warning(f"Ошибка распаковки основного архива: {extraction_result}")
                scan_results[filename] = {"status": "ERROR", "error": extraction_result}
            else:
                scan_results[filename] = archive_structure
        else:
            with open(file_path, "rb") as f:
                result = clamav.scan_stream(f.read())
                scan_results[filename] = {"status": result["stream"] if result else "CLEAN"}
            extracted_files = [(file_path, filename, None)]

        logger.debug(f"scan_results перед возвратом: {scan_results}")

        # Логирование в БД
        db.session.add(ScanLog(token=token, filename=filename, result=len(extracted_files), description=token_desc))
        db.session.commit()

        total_requests = db.session.query(db.func.sum(cast(ScanLog.result, Integer))).filter_by(token=token).scalar() or 0
        total_requests_count = db.session.query(db.func.count(ScanLog.id)).filter_by(token=token).scalar() or 0

        clamav_requests_metric.labels(token=token_desc).set(total_requests)
        clamav_requests_count_metric.labels(token=token_desc).set(total_requests_count)

    except Exception as e:
        logger.error(f"Ошибка при сканировании: {str(e)}")
        scan_results[filename] = {"status": "ERROR", "error": str(e)}
        return jsonify(scan_results), 500

    finally:
        try:
            shutil.rmtree(unique_folder)
        except Exception as e:
            logger.warning(f"Не удалось удалить временную папку {unique_folder}: {e}")

    return jsonify(scan_results)

if __name__ == "__main__":
    def run_prometheus_server():
        start_http_server(9044)
        logger.info("Exporter is running on http://localhost:9044")

    prometheus_thread = threading.Thread(target=run_prometheus_server)
    prometheus_thread.daemon = True
    prometheus_thread.start()

    app.run(host="0.0.0.0", port=5000)
