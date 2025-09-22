# =======================================================================
# CM REURB v2.1 - Backend Flask (CORS e Preflight corrigidos + PGV + Dashboard)
# =======================================================================

import os
import datetime
from functools import wraps
import jwt  # PyJWT

import pandas as pd
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =======================================================================
# ⚙️ CONFIGURAÇÃO DA APLICAÇÃO
# =======================================================================

app = Flask(__name__)

# 🔹 CORS configurado corretamente para todos os endpoints da API
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

SECRET_KEY = os.environ.get('SECRET_KEY', 'chave-secreta-para-desenvolvimento-muito-segura-trocar-em-producao')
DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://reurb_user:123@localhost:5432/reurb_apk')
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =======================================================================
# MODELS
# =======================================================================

class Usuario(db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    usuario = db.Column(db.String(50), unique=True, nullable=False)
    senha_hash = db.Column(db.String(1024), nullable=False)
    acesso = db.Column(db.String(20), nullable=False, default='Usuario')

    def __init__(self, nome, usuario, senha, acesso='Usuario'):
        self.nome = nome
        self.usuario = usuario
        self.senha_hash = generate_password_hash(senha, method="scrypt")
        self.acesso = acesso

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)


class CadastroReurb(db.Model):
    __tablename__ = 'cadastros_reurb'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(50), default='Em Análise')
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    data_criacao = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    data_atualizacao = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    req_nome = db.Column(db.String(150))
    req_cpf = db.Column(db.String(20))
    req_rg = db.Column(db.String(20))
    req_data_nasc = db.Column(db.String(20))
    req_nacionalidade = db.Column(db.String(50))
    req_estado_civil = db.Column(db.String(30))
    conj_nome = db.Column(db.String(150))
    conj_cpf = db.Column(db.String(20))
    req_profissao = db.Column(db.String(100))
    req_telefone = db.Column(db.String(30))
    req_email = db.Column(db.String(150))
    imovel_cep = db.Column(db.String(15))
    imovel_logradouro = db.Column(db.String(150))
    imovel_numero = db.Column(db.String(20))
    imovel_complemento = db.Column(db.String(100))
    imovel_bairro = db.Column(db.String(100))
    imovel_cidade = db.Column(db.String(100))
    imovel_uf = db.Column(db.String(2))
    inscricao_imobiliaria = db.Column(db.String(30), index=True)
    imovel_area_total = db.Column(db.Float)
    imovel_area_construida = db.Column(db.Float)
    imovel_uso = db.Column(db.String(30))
    imovel_tipo_construcao = db.Column(db.String(30))
    reurb_renda_familiar = db.Column(db.Float)
    reurb_outro_imovel = db.Column(db.String(10))


class Documento(db.Model):
    __tablename__ = 'documentos'
    id = db.Column(db.Integer, primary_key=True)
    cadastro_id = db.Column(db.Integer, db.ForeignKey('cadastros_reurb.id'), nullable=False)
    nome_arquivo = db.Column(db.String(255), nullable=False)
    path_arquivo = db.Column(db.String(512), nullable=False)
    tipo_documento = db.Column(db.String(100))
    data_upload = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    cadastro = db.relationship("CadastroReurb", backref=db.backref("documentos", lazy=True, cascade="all, delete-orphan"))


class PadraoConstrutivo(db.Model):
    __tablename__ = 'padroes_construtivos'
    id = db.Column(db.Integer, primary_key=True)
    descricao = db.Column(db.String(150), nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class ValorLogradouro(db.Model):
    __tablename__ = 'valores_logradouro'
    id = db.Column(db.Integer, primary_key=True)
    logradouro = db.Column(db.String(150), unique=True, nullable=False)
    valor_m2 = db.Column(db.Float, nullable=False)


class AliquotaIPTU(db.Model):
    __tablename__ = 'aliquotas_iptu'
    id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(150), unique=True, nullable=False)
    aliquota = db.Column(db.Float, nullable=False)

# =======================================================================
# SERVIÇOS E UTILIDADES
# =======================================================================

class CalculoTributarioService:
    @staticmethod
    def calcular_valores(cadastro: CadastroReurb):
        vvt, vvc, vvi, iptu = 0.0, 0.0, 0.0, 0.0
        
        try:
            if cadastro.imovel_logradouro and cadastro.imovel_area_total:
                logradouro = ValorLogradouro.query.filter_by(logradouro=cadastro.imovel_logradouro).first()
                if logradouro:
                    vvt = cadastro.imovel_area_total * logradouro.valor_m2

            if cadastro.imovel_tipo_construcao and cadastro.imovel_area_construida:
                padrao = PadraoConstrutivo.query.filter_by(descricao=cadastro.imovel_tipo_construcao).first()
                if padrao:
                    vvc = cadastro.imovel_area_construida * padrao.valor_m2

            vvi = vvt + vvc

            if cadastro.imovel_uso:
                aliquota_data = AliquotaIPTU.query.filter_by(tipo=cadastro.imovel_uso).first()
                if aliquota_data:
                    iptu = vvi * aliquota_data.aliquota

        except Exception as e:
            print(f"Erro no cálculo: {e}")
        
        return {
            "vvt": vvt,
            "vvc": vvc,
            "vvi": vvi,
            "iptu": iptu
        }

# =======================================================================
# DECORADORES AJUSTADOS PARA CORS PRE-FLIGHT
# =======================================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return jsonify({'status': 'ok'}), 200  # permite preflight

        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'mensagem': 'Token inválido!'}), 401

        if not token:
            return jsonify({'mensagem': 'Token de autenticação ausente!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.filter_by(id=data['public_id']).first()
        except jwt.ExpiredSignatureError:
            return jsonify({'mensagem': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensagem': 'Token inválido!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'OPTIONS':
            return jsonify({'status': 'ok'}), 200  # permite preflight

        token = None
        if 'Authorization' in request.headers:
            try:
                auth_header = request.headers['Authorization']
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'mensagem': 'Token inválido!'}), 401

        if not token:
            return jsonify({'mensagem': 'Token de autenticação ausente!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if data.get('acesso') != 'Administrador':
                return jsonify({'mensagem': 'Permissão negada. Apenas administradores podem acessar.'}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({'mensagem': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensagem': 'Token inválido!'}), 401

        return f(*args, **kwargs)
    return decorated

# =======================================================================
# ROTAS DA API
# =======================================================================

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json()
    usuario = data.get('usuario')
    senha = data.get('senha')
    user = Usuario.query.filter_by(usuario=usuario).first()
    if user and user.verificar_senha(senha):
        token = jwt.encode({
            'public_id': user.id,
            'usuario': user.usuario,
            'acesso': user.acesso,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({
            'mensagem': 'Login bem-sucedido!',
            'token': token,
            'nome_usuario': user.nome,
            'acesso': user.acesso
        }), 200
    return jsonify({'mensagem': 'Login ou senha incorretos.'}), 401


@app.route('/api/cadastrar_reurb', methods=['POST', 'OPTIONS'])
@token_required
def cadastrar_reurb(current_user):
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    data = request.get_json()
    try:
        novo_cadastro = CadastroReurb(
            req_nome=data.get('req_nome'),
            req_cpf=data.get('req_cpf'),
            req_rg=data.get('req_rg'),
            req_data_nasc=data.get('req_data_nasc'),
            req_nacionalidade=data.get('req_nacionalidade'),
            req_estado_civil=data.get('req_estado_civil'),
            conj_nome=data.get('conj_nome'),
            conj_cpf=data.get('conj_cpf'),
            req_profissao=data.get('req_profissao'),
            req_telefone=data.get('req_telefone'),
            req_email=data.get('req_email'),
            imovel_cep=data.get('imovel_cep'),
            imovel_logradouro=data.get('imovel_logradouro'),
            imovel_numero=data.get('imovel_numero'),
            imovel_complemento=data.get('imovel_complemento'),
            imovel_bairro=data.get('imovel_bairro'),
            imovel_cidade=data.get('imovel_cidade'),
            imovel_uf=data.get('imovel_uf'),
            inscricao_imobiliaria=data.get('inscricao_imobiliaria'),
            imovel_area_total=float(data.get('imovel_area_total') or 0),
            imovel_area_construida=float(data.get('imovel_area_construida') or 0),
            imovel_uso=data.get('imovel_uso'),
            imovel_tipo_construcao=data.get('imovel_tipo_construcao'),
            reurb_renda_familiar=float(data.get('reurb_renda_familiar') or 0),
            reurb_outro_imovel=data.get('reurb_outro_imovel')
        )
        db.session.add(novo_cadastro)
        db.session.commit()
        return jsonify({'mensagem': 'Cadastro REURB criado com sucesso!', 'id': novo_cadastro.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'mensagem': f'Erro ao criar cadastro: {str(e)}'}), 400


@app.route('/api/cadastros', methods=['GET', 'OPTIONS'])
@token_required
def get_cadastros(current_user):
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    cadastros = CadastroReurb.query.all()
    output = []
    for cad in cadastros:
        output.append({
            'id': cad.id,
            'inscricao_imobiliaria': cad.inscricao_imobiliaria,
            'imovel_logradouro': cad.imovel_logradouro,
            'imovel_numero': cad.imovel_numero,
            'imovel_bairro': cad.imovel_bairro,
            'imovel_area_total': cad.imovel_area_total,
            'imovel_area_construida': cad.imovel_area_construida
        })
    return jsonify(output)

# =======================================================================
# ROTAS DA PGV (Planta Genérica)
# =======================================================================

@app.route('/api/planta_generica/padroes', methods=['GET', 'POST', 'OPTIONS'])
def planta_padroes():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    if request.method == 'POST':
        data = request.get_json()
        try:
            novo = PadraoConstrutivo(
                descricao=data.get('descricao'),
                valor_m2=float(data.get('valor_m2') or 0)
            )
            db.session.add(novo)
            db.session.commit()
            return jsonify({'mensagem': 'Padrão cadastrado com sucesso!'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'mensagem': f'Erro ao salvar padrão: {str(e)}'}), 400
    padroes = PadraoConstrutivo.query.all()
    return jsonify([
        {'id': p.id, 'descricao': p.descricao, 'valor_m2': p.valor_m2}
        for p in padroes
    ]), 200


@app.route('/api/planta_generica/logradouros', methods=['GET', 'POST', 'OPTIONS'])
def planta_logradouros():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    if request.method == 'POST':
        data = request.get_json()
        try:
            novo = ValorLogradouro(
                logradouro=data.get('logradouro'),
                valor_m2=float(data.get('valor_m2') or 0)
            )
            db.session.add(novo)
            db.session.commit()
            return jsonify({'mensagem': 'Logradouro cadastrado com sucesso!'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'mensagem': f'Erro ao salvar logradouro: {str(e)}'}), 400
    logradouros = ValorLogradouro.query.all()
    return jsonify([
        {'id': l.id, 'logradouro': l.logradouro, 'valor_m2': l.valor_m2}
        for l in logradouros
    ]), 200


@app.route('/api/planta_generica/aliquotas', methods=['GET', 'POST', 'OPTIONS'])
def planta_aliquotas():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    if request.method == 'POST':
        data = request.get_json()
        try:
            novo = AliquotaIPTU(
                tipo=data.get('tipo'),
                aliquota=float(data.get('aliquota') or 0)
            )
            db.session.add(novo)
            db.session.commit()
            return jsonify({'mensagem': 'Alíquota cadastrada com sucesso!'}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({'mensagem': f'Erro ao salvar alíquota: {str(e)}'}), 400
    aliquotas = AliquotaIPTU.query.all()
    return jsonify([
        {'id': a.id, 'tipo': a.tipo, 'aliquota': a.aliquota}
        for a in aliquotas
    ]), 200

# =======================================================================
# ROTA DO DASHBOARD
# =======================================================================

@app.route('/api/dashboard', methods=['GET', 'OPTIONS'])
def dashboard():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'}), 200
    try:
        total_cadastros = CadastroReurb.query.count()
        cadastros = CadastroReurb.query.all()
        iptu_total = 0
        for cad in cadastros:
            valores = CalculoTributarioService.calcular_valores(cad)
            iptu_total += valores['iptu']
        solicitacoes = CadastroReurb.query.filter_by(status='Em Análise').count()
        alertas = CadastroReurb.query.filter(
            (CadastroReurb.inscricao_imobiliaria == None) |
            (CadastroReurb.inscricao_imobiliaria == "")
        ).count()
        return jsonify({
            'total_cadastros': total_cadastros,
            'iptu_total': iptu_total,
            'solicitacoes': solicitacoes,
            'alertas': alertas
        }), 200
    except Exception as e:
        return jsonify({'mensagem': f'Erro ao carregar dashboard: {str(e)}'}), 500

# =======================================================================
# MAIN
# =======================================================================

if __name__ == '__main__':
    app.run(debug=True)
