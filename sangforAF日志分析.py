import streamlit as st
import pandas as pd
import io
import json
import os
import re
import time
import requests
import ipaddress

# =================== 页面配置 ===================
st.set_page_config(page_title="防火墙日志分析助手", layout="wide")
st.title("🛡️ 防火墙日志分析平台")
st.markdown("动态列白名单 | 支持逗号分隔、端口范围、排除匹配(!) | Payload命中即确认")

# =================== 配置文件管理 ===================
CONFIG_FILE = "config.json"
PAYLOAD_FILE = "payload_dict.txt"

VT_API_KEY = ""
VT_BASE_URL = "https://www.virustotal.com/api/v3"

def load_config():
    default = {"trusted_rules": []}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return default
    else:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(default, f, indent=4, ensure_ascii=False)
        return default

def save_config(config):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

def load_payload_dict():
    payloads = []
    if os.path.exists(PAYLOAD_FILE):
        try:
            with open(PAYLOAD_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        payloads.append(line)
        except Exception as e:
            st.warning(f"加载Payload字典失败: {e}")
    if not payloads:
        payloads = [
            '/etc/passwd', '../../../../etc/passwd', '/win.ini',
            'input.bat?input=calc', '${jndi:ldap://', '${jndi:rmi://',
            '/actuator/', '/actuator/env', '/.git/config', '/.svn/entries',
            '/WEB-INF/web.xml', '/WEB-INF/jboss-web.xml',
            '/storage/logs/laravel.log',
            '/current_config/Sha1Account1', '/nacos/v1/auth/users/',
            "/api/file/downloadFile?file=",
            "' OR '1'='1", "' UNION SELECT "
        ]
    return payloads

# =================== IP 工具函数 ===================
def is_valid_ip_pattern(ip_str):
    ip_str = ip_str.strip()
    if not ip_str:
        return True
    parts = [p.strip() for p in ip_str.split(',') if p.strip()]
    if not parts:
        return False
    for item in parts:
        if '/' in item:
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError:
                return False
        elif '-' in item:
            sub = item.split('-')
            if len(sub) == 2:
                try:
                    ipaddress.ip_address(sub[0].strip())
                    ipaddress.ip_address(sub[1].strip())
                except ValueError:
                    return False
            else:
                return False
        else:
            try:
                ipaddress.ip_address(item)
            except ValueError:
                return False
    return True

def ip_matches(ip_str, rule_ip):
    if not rule_ip or not rule_ip.strip():
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    parts = [p.strip() for p in rule_ip.split(',') if p.strip()]
    for item in parts:
        if '/' in item:
            try:
                network = ipaddress.ip_network(item, strict=False)
                if ip_obj in network:
                    return True
            except ValueError:
                continue
        elif '-' in item:
            sub = item.split('-')
            if len(sub) == 2:
                try:
                    start = ipaddress.ip_address(sub[0].strip())
                    end = ipaddress.ip_address(sub[1].strip())
                    if start <= ip_obj <= end:
                        return True
                except ValueError:
                    continue
        else:
            if ip_str == item:
                return True
    return False

def column_value_matches(actual_value, expected_value, column_name=''):
    actual_str = str(actual_value).strip()
    expected_str = str(expected_value).strip()
    if not expected_str:
        return True

    if column_name in ['源端口', '目的端口'] and '-' in expected_str:
        parts = expected_str.split('-')
        if len(parts) == 2:
            try:
                start = int(parts[0].strip())
                end = int(parts[1].strip())
                actual_port = int(actual_str)
                return start <= actual_port <= end
            except (ValueError, TypeError):
                pass

    if ',' in expected_str:
        parts = [p.strip() for p in expected_str.split(',') if p.strip()]
        for p in parts:
            if p.startswith('!'):
                exclude = p[1:].strip()
                if exclude in actual_str:
                    return False
            else:
                if p in actual_str:
                    return True
        return False

    if expected_str.startswith('!'):
        exclude = expected_str[1:].strip()
        return exclude not in actual_str

    return expected_str in actual_str

# =================== 威胁情报 ===================
class ThreatIntel:
    def __init__(self):
        self.vt_api_key = VT_API_KEY
        self.last_request_time = 0
        self.min_interval = 15

    def _rate_limit(self):
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_request_time = time.time()

    def check_ip_vt(self, ip):
        if not self.vt_api_key:
            return None, "未配置VirusTotal API Key"
        if ip.startswith(('172.16.', '192.168.', '10.', '127.', '0.')):
            return None, "内网IP，跳过查询"
        self._rate_limit()
        url = f"{VT_BASE_URL}/ip_addresses/{ip}"
        headers = {"x-apikey": self.vt_api_key, "accept": "application/json"}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get('data', {}).get('attributes', {})
                stats = attrs.get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                tags = attrs.get('tags', [])[:3]
                return {
                    'malicious': malicious,
                    'total_engines': total,
                    'tags': tags,
                    'country': attrs.get('country', 'N/A'),
                    'as_owner': attrs.get('as_owner', 'N/A')
                }, None
            elif resp.status_code == 404:
                return None, f"IP {ip} 无VirusTotal记录"
            else:
                return None, f"VT API错误: {resp.status_code}"
        except Exception as e:
            return None, f"VT查询失败: {str(e)}"

intel = ThreatIntel()

# =================== Session State 初始化 ===================
if 'config' not in st.session_state:
    st.session_state.config = load_config()
if 'payload_dict' not in st.session_state:
    st.session_state.payload_dict = load_payload_dict()
if 'df' not in st.session_state:
    st.session_state.df = None
if 'df_marked' not in st.session_state:
    st.session_state.df_marked = None
if 'filter_levels' not in st.session_state:
    st.session_state.filter_levels = ['严重', '高危', '中危', '低危', '信息', '未知']
if 'filter_conditions' not in st.session_state:
    st.session_state.filter_conditions = []
if 'enable_threat_intel' not in st.session_state:
    st.session_state.enable_threat_intel = False
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
if 'edit_rule_index' not in st.session_state:
    st.session_state.edit_rule_index = -1
if 'clone_rule_data' not in st.session_state:
    st.session_state.clone_rule_data = None
if 'add_editor_key' not in st.session_state:
    st.session_state.add_editor_key = 0
if 'edit_editor_key' not in st.session_state:
    st.session_state.edit_editor_key = 0

def get_default_conditions_df():
    return pd.DataFrame([{'列名': '', '匹配值': ''}])

if 'add_conditions_df' not in st.session_state:
    st.session_state.add_conditions_df = get_default_conditions_df()
if 'edit_conditions_df' not in st.session_state:
    st.session_state.edit_conditions_df = pd.DataFrame(columns=['列名', '匹配值'])

# =================== 获取可用列名（合并规则中的列） ===================
def get_available_columns(df=None):
    if df is not None:
        all_cols = list(df.columns)
        exclude_cols = ['标记等级', '标记图标', '标记说明', '基础等级', '基础图标', '基础说明', '源IP']
        base_cols = [col for col in all_cols if col not in exclude_cols]
    else:
        base_cols = ['目的IP', '源端口', '目的端口', '攻击类型', '严重等级', '描述', '动作', '协议', '日志类型']
    
    rules = st.session_state.config.get('trusted_rules', [])
    extra_cols = set()
    for rule in rules:
        for cond in rule.get('conditions', []):
            col = cond.get('column', '').strip()
            if col:
                extra_cols.add(col)
    combined = base_cols + [col for col in extra_cols if col not in base_cols]
    return combined

# =================== 白名单检查与标记 ===================
def check_whitelist(row, rules):
    src_ip = str(row.get('源IP', ''))
    for rule in rules:
        rule_ip = rule.get('ip', '')
        if not ip_matches(src_ip, rule_ip):
            continue
        conditions = rule.get('conditions', [])
        if not conditions:
            return True, rule.get('comment', '无条件匹配')
        all_match = True
        for cond in conditions:
            col_name = cond.get('column', '')
            expected_value = cond.get('value', '')
            if not col_name or not expected_value:
                continue
            actual_value = row.get(col_name, '')
            if not column_value_matches(actual_value, expected_value, col_name):
                all_match = False
                break
        if all_match:
            return True, rule.get('comment', '动态列条件匹配')
    return False, ""

def compute_base_mark(row, payload_dict, enable_intel):
    attack_type = str(row.get('攻击类型', ''))
    severity = str(row.get('严重等级', ''))
    description = str(row.get('描述', ''))
    
    if '感染病毒' in attack_type or '木马' in attack_type:
        base_level, base_icon, base_reason = '高危', '🔴', '病毒/木马行为'
    elif '高危' in severity or '龙腾CMS' in description or '远程代码执行' in description:
        base_level, base_icon, base_reason = '高危', '🔴', '高危漏洞利用'
    elif '漏洞攻击' in attack_type or '扫描工具' in attack_type or '黑客工具' in attack_type:
        base_level, base_icon, base_reason = '中危', '🟠', '漏洞扫描/攻击'
    elif '中危' in severity or 'CVE-' in description:
        base_level, base_icon, base_reason = '中危', '🟠', '漏洞利用尝试'
    elif '流量异常' in attack_type or '反弹连接' in description:
        base_level, base_icon, base_reason = '低危', '🔵', '异常连接'
    elif '信息泄露' in attack_type or '信息' in severity:
        base_level, base_icon, base_reason = '信息', '🟣', '信息探测'
    else:
        base_level, base_icon, base_reason = '未知', '⚪', '未识别'

    payload = str(row.get('数据包', ''))
    if payload and payload not in ['LQ==', 'nan', '']:
        clean_text = payload.replace('<br>', '\n')
        request_part = ''
        if 'REQUEST:' in clean_text:
            request_part = clean_text.split('REQUEST:')[-1]
            if 'RESPONSE:' in request_part:
                request_part = request_part.split('RESPONSE:')[0]
        if request_part:
            request_lower = request_part.lower()
            matched = []
            for p in payload_dict:
                if p.lower() in request_lower:
                    matched.append(p)
            if matched:
                matched_str = ' | '.join(matched[:3])
                status_code = None
                if 'RESPONSE:' in clean_text:
                    resp_part = clean_text.split('RESPONSE:')[-1]
                    code_match = re.search(r'HTTP/1\.\d\s+(\d{3})', resp_part)
                    if code_match:
                        status_code = int(code_match.group(1))
                if status_code == 200:
                    return ('已确认', '✅', f'命中Payload且响应200，特征: {matched_str}')
                elif status_code == 404:
                    return ('已确认', '✅', f'命中Payload但响应404，特征: {matched_str}')
                else:
                    return ('已确认', '✅', f'命中Payload特征，特征: {matched_str}')
    
    if enable_intel:
        src_ip = str(row.get('源IP', ''))
        if src_ip and not src_ip.startswith(('172.16.', '192.168.', '10.', '127.', '0.')):
            vt_info, vt_error = intel.check_ip_vt(src_ip)
            if vt_info and vt_info.get('malicious', 0) > 0:
                malicious = vt_info['malicious']
                total = vt_info['total_engines']
                tags = ', '.join(vt_info.get('tags', []))
                if base_level in ['低危', '信息', '未知']:
                    return ('高危', '🔴', f'VT确认恶意 ({malicious}/{total})，标签: {tags}')
                else:
                    base_reason = f'{base_reason}，VT检测: {malicious}/{total} 引擎报毒'
    
    return (base_level, base_icon, base_reason)

def apply_whitelist_to_row(row, rules):
    is_whitelisted, comment = check_whitelist(row, rules)
    if is_whitelisted:
        return ('已确认', '✅', f'✅ {comment}')
    else:
        return (row.get('基础等级', '未知'), row.get('基础图标', '⚪'), row.get('基础说明', '未识别'))

def apply_whitelist_to_df(df, rules):
    if df is None or len(df) == 0:
        return df
    if '基础等级' not in df.columns:
        return df
    df = df.copy()
    final_marks = df.apply(lambda row: apply_whitelist_to_row(row, rules), axis=1, result_type='expand')
    final_marks.columns = ['标记等级', '标记图标', '标记说明']
    for col in final_marks.columns:
        df[col] = final_marks[col]
    return df

def process_dataframe(df, rules, payload_dict, enable_intel):
    if df is None or len(df) == 0:
        return df
    base_marks = df.apply(lambda row: compute_base_mark(row, payload_dict, enable_intel), axis=1, result_type='expand')
    base_marks.columns = ['基础等级', '基础图标', '基础说明']
    df = pd.concat([df, base_marks], axis=1)
    return apply_whitelist_to_df(df, rules)

# =================== 加载数据 ===================
def load_data(uploaded_file):
    try:
        if uploaded_file.name.endswith('.xlsx'):
            df = pd.read_excel(uploaded_file, skiprows=7)
        else:
            df = pd.read_csv(uploaded_file, skiprows=7)
        df.dropna(how='all', inplace=True)
        return df
    except Exception as e:
        st.error(f"读取失败: {e}")
        return None

# =================== 更新规则并刷新 ===================
def update_rules_and_refresh(new_rules):
    st.session_state.config['trusted_rules'] = new_rules
    save_config(st.session_state.config)
    if st.session_state.df_marked is not None:
        st.session_state.df_marked = apply_whitelist_to_df(st.session_state.df_marked, new_rules)
    st.session_state.add_editor_key += 1
    st.session_state.edit_editor_key += 1
    st.rerun()

# =================== 侧边栏 ===================
with st.sidebar:
    st.header("⚙️ 白名单规则")
    st.caption("💡 所有列均支持逗号分隔多个值（OR匹配），端口列支持范围（如 55000-56000），前缀 `!` 表示排除匹配")

    rules = st.session_state.config.get('trusted_rules', [])
    
    # ---- 编辑模式 ----
    if st.session_state.edit_rule_index >= 0:
        st.info(f"✏️ 正在编辑规则 #{st.session_state.edit_rule_index + 1}")
        edit_idx = st.session_state.edit_rule_index
        edit_rule = rules[edit_idx] if edit_idx < len(rules) else None
        if edit_rule:
            current_columns = get_available_columns(st.session_state.df)
            with st.form("edit_rule_form", clear_on_submit=False):
                new_ip = st.text_input(
                    "源IP匹配（留空匹配所有）",
                    value=edit_rule.get('ip', ''),
                    help="支持单个IP、CIDR、范围，多个用逗号分隔。"
                )
                new_comment = st.text_input("备注", value=edit_rule.get('comment', ''))
                
                st.caption("条件列表（可留空，留空则仅通过源IP匹配）")
                st.caption("💡 所有列均支持逗号分隔多个值；端口列额外支持范围；前缀 `!` 表示排除")
                
                edit_key = f"edit_conditions_editor_{st.session_state.edit_editor_key}"
                edited_df = st.data_editor(
                    st.session_state.edit_conditions_df,
                    column_config={
                        "列名": st.column_config.SelectboxColumn(
                            "列名",
                            options=current_columns,
                            required=False
                        ),
                        "匹配值": st.column_config.TextColumn(
                            "匹配值",
                            required=False,
                            help="逗号分隔多个值，端口支持范围，前缀!排除"
                        )
                    },
                    num_rows="dynamic",
                    use_container_width=True,
                    key=edit_key
                )
                st.session_state.edit_conditions_df = edited_df
                
                st.divider()
                col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
                with col_btn1:
                    if st.form_submit_button("💾 保存", use_container_width=True):
                        new_ip_value = new_ip.strip()
                        if new_ip_value and not is_valid_ip_pattern(new_ip_value):
                            st.error(f"IP格式无效: '{new_ip_value}'")
                        else:
                            valid_conds = []
                            for _, row in edited_df.iterrows():
                                col_name = str(row.get('列名', '')).strip()
                                val = str(row.get('匹配值', '')).strip()
                                if col_name and val and val.lower() != 'nan':
                                    valid_conds.append({"column": col_name, "value": val})
                            rules[edit_idx] = {
                                "ip": new_ip_value,
                                "comment": new_comment.strip() or "",
                                "conditions": valid_conds
                            }
                            st.session_state.edit_rule_index = -1
                            st.session_state.edit_conditions_df = pd.DataFrame(columns=['列名', '匹配值'])
                            st.session_state.edit_editor_key += 1
                            update_rules_and_refresh(rules)
                            st.stop()
                with col_btn2:
                    if st.form_submit_button("❌ 取消", use_container_width=True):
                        st.session_state.edit_rule_index = -1
                        st.session_state.edit_conditions_df = pd.DataFrame(columns=['列名', '匹配值'])
                        st.session_state.edit_editor_key += 1
                        st.rerun()
        else:
            st.error("规则不存在")
            st.session_state.edit_rule_index = -1
            st.rerun()
        st.divider()
    else:
        # ---- 添加规则（顶部，默认展开） ----
        clone_data = st.session_state.clone_rule_data
        is_clone_mode = clone_data is not None
        
        with st.expander("➕ 添加新规则", expanded=is_clone_mode or True):
            if is_clone_mode:
                st.info(f"📋 正在克隆规则：{clone_data.get('comment', '未命名')}")
            
            with st.form("add_rule_form", clear_on_submit=True):
                default_ip = clone_data.get('ip', '') if is_clone_mode else ''
                default_comment = clone_data.get('comment', '') if is_clone_mode else ''
                
                ip_input = st.text_input(
                    "源IP匹配（留空匹配所有）",
                    value=default_ip,
                    placeholder="例如: 192.168.1.1 或 192.168.1.0/24",
                    help="支持单个IP、CIDR、范围，多个用逗号分隔。"
                )
                comment_input = st.text_input("备注", value=default_comment, placeholder="例如: 可信服务")
                
                st.caption("条件列表（可留空，留空则仅通过源IP匹配）")
                st.caption("💡 所有列均支持逗号分隔多个值；端口列额外支持范围；前缀 `!` 表示排除")
                
                if is_clone_mode and clone_data.get('conditions'):
                    clone_conds = clone_data.get('conditions', [])
                    if clone_conds:
                        current_df = pd.DataFrame(clone_conds)
                        if '列名' not in current_df.columns or '匹配值' not in current_df.columns:
                            current_df = get_default_conditions_df()
                    else:
                        current_df = get_default_conditions_df()
                else:
                    current_df = st.session_state.add_conditions_df
                
                current_columns = get_available_columns(st.session_state.df)
                
                add_key = f"add_conditions_editor_{st.session_state.add_editor_key}"
                edited_df = st.data_editor(
                    current_df,
                    column_config={
                        "列名": st.column_config.SelectboxColumn(
                            "列名",
                            options=current_columns,
                            required=False
                        ),
                        "匹配值": st.column_config.TextColumn(
                            "匹配值",
                            required=False,
                            help="逗号分隔多个值，端口支持范围，前缀!排除"
                        )
                    },
                    num_rows="dynamic",
                    use_container_width=True,
                    key=add_key
                )
                
                st.session_state.add_conditions_df = edited_df
                
                submitted = st.form_submit_button("✅ 保存规则")
                
                if submitted:
                    ip_value = ip_input.strip()
                    if ip_value and not is_valid_ip_pattern(ip_value):
                        st.error(f"IP格式无效: '{ip_value}'")
                    else:
                        valid_conds = []
                        for _, row in edited_df.iterrows():
                            col_name = str(row.get('列名', '')).strip()
                            val = str(row.get('匹配值', '')).strip()
                            if col_name and val and val.lower() != 'nan':
                                valid_conds.append({"column": col_name, "value": val})
                        new_rule = {
                            "ip": ip_value,
                            "comment": comment_input.strip() or "",
                            "conditions": valid_conds
                        }
                        exists = any(
                            r.get('ip') == new_rule['ip'] and 
                            r.get('conditions') == new_rule['conditions']
                            for r in rules
                        )
                        if exists:
                            st.warning("该规则已存在")
                        else:
                            rules.append(new_rule)
                            st.session_state.clone_rule_data = None
                            st.session_state.add_conditions_df = get_default_conditions_df()
                            st.session_state.add_editor_key += 1
                            update_rules_and_refresh(rules)
                            st.stop()
            
            if is_clone_mode:
                if st.button("❌ 取消克隆", use_container_width=True):
                    st.session_state.clone_rule_data = None
                    st.session_state.add_conditions_df = get_default_conditions_df()
                    st.session_state.add_editor_key += 1
                    st.rerun()
        
        st.divider()
        
        # ---- 显示已有规则 ----
        if rules:
            st.write("**当前规则：**")
            for idx, rule in enumerate(rules):
                ip = rule.get('ip', '')
                display_ip = ip if ip else '【匹配所有IP】'
                comment = rule.get('comment', '')
                conditions = rule.get('conditions', [])
                cond_count = len(conditions)
                
                with st.expander(f"📌 {display_ip} {comment} ({cond_count}个条件)"):
                    st.write(f"**IP规则**: `{display_ip}`")
                    if conditions:
                        for cond in conditions:
                            val = cond.get('value', '')
                            st.write(f"  - {cond.get('column', '')} → `{val}`")
                    else:
                        st.write("  - ⚪ 无条件（匹配所有日志）")
                    
                    col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
                    with col_btn1:
                        if st.button("✏️ 编辑", key=f"edit_rule_{idx}", use_container_width=True):
                            rule = rules[idx]
                            conds = rule.get('conditions', [])
                            if conds:
                                st.session_state.edit_conditions_df = pd.DataFrame(conds)
                            else:
                                st.session_state.edit_conditions_df = pd.DataFrame(columns=['列名', '匹配值'])
                            st.session_state.edit_rule_index = idx
                            st.session_state.edit_editor_key += 1
                            st.rerun()
                    with col_btn2:
                        if st.button("📋 克隆", key=f"clone_rule_{idx}", use_container_width=True):
                            st.session_state.clone_rule_data = {
                                "ip": rule.get('ip', ''),
                                "comment": rule.get('comment', ''),
                                "conditions": rule.get('conditions', [])
                            }
                            st.session_state.add_conditions_df = get_default_conditions_df()
                            st.session_state.add_editor_key += 1
                            st.rerun()
                    with col_btn3:
                        if st.button("🗑️ 删除", key=f"del_rule_{idx}", use_container_width=True):
                            rules.pop(idx)
                            update_rules_and_refresh(rules)
                            st.stop()
        else:
            st.info("暂无规则")
    
    st.divider()
    st.header("🧬 Payload字典")
    st.caption(f"已加载 {len(st.session_state.payload_dict)} 条特征")
    with st.expander("查看列表"):
        for p in st.session_state.payload_dict[:20]:
            st.code(p, language=None)

    st.divider()
    st.header("⚡ 性能设置")
    enable_intel = st.toggle(
        "威胁情报（VirusTotal）",
        value=st.session_state.enable_threat_intel,
        help="开启后查询外部API，耗时增加"
    )
    if enable_intel != st.session_state.enable_threat_intel:
        st.session_state.enable_threat_intel = enable_intel
        st.session_state.analysis_complete = False
        st.rerun()
    
    st.divider()
    if st.button("🗑️ 清除数据", use_container_width=True):
        st.session_state.df = None
        st.session_state.df_marked = None
        st.session_state.analysis_complete = False
        st.session_state.filter_conditions = []
        st.session_state.edit_rule_index = -1
        st.session_state.clone_rule_data = None
        st.session_state.add_conditions_df = get_default_conditions_df()
        st.session_state.edit_conditions_df = pd.DataFrame(columns=['列名', '匹配值'])
        st.session_state.add_editor_key += 1
        st.session_state.edit_editor_key += 1
        st.rerun()

# =================== 主界面 ===================
uploaded_file = st.file_uploader("📂 上传日志 (.xlsx / .csv)", type=['xlsx', 'csv'])

if uploaded_file is not None:
    df = load_data(uploaded_file)
    if df is not None:
        st.session_state.df = df
        st.session_state.analysis_complete = False
        st.session_state.add_editor_key += 1
        st.session_state.edit_editor_key += 1
        st.success(f"✅ 已缓存 {len(df)} 条日志")
    else:
        st.session_state.df = None

if st.session_state.df is not None:
    df = st.session_state.df

    with st.expander("📋 原始数据预览"):
        st.dataframe(df.head())

    if not st.session_state.analysis_complete or st.session_state.df_marked is None:
        rules = st.session_state.config.get('trusted_rules', [])
        payload_dict = st.session_state.payload_dict
        enable_intel = st.session_state.enable_threat_intel

        with st.spinner("🔍 正在分析..."):
            start_time = time.time()
            st.session_state.df_marked = process_dataframe(df, rules, payload_dict, enable_intel)
            elapsed = time.time() - start_time
            st.session_state.analysis_complete = True
            st.toast(f"✅ 分析完成，耗时 {elapsed:.2f} 秒", icon="✅")

    df_marked = st.session_state.df_marked

    # ---- 统计 ----
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("📊 总数", len(df_marked))
    with col2:
        st.metric("🔥 严重", len(df_marked[df_marked['标记等级'] == '严重']))
    with col3:
        st.metric("🔴 高危", len(df_marked[df_marked['标记等级'] == '高危']))
    with col4:
        st.metric("🟠 中危", len(df_marked[df_marked['标记等级'] == '中危']))
    with col5:
        st.metric("✅ 已确认", len(df_marked[df_marked['标记等级'] == '已确认']))

    st.subheader("📈 等级分布")
    st.dataframe(df_marked['标记等级'].value_counts().reset_index())

    # ---- 筛选 ----
    st.subheader("📑 详细分析结果")

    col_filter1, col_filter2 = st.columns([1, 2])
    with col_filter1:
        all_levels = ['严重', '高危', '中危', '低危', '信息', '已确认', '未知']
        selected_levels = st.multiselect(
            "等级筛选",
            options=all_levels,
            default=st.session_state.filter_levels,
            key="filter_levels_widget"
        )
        st.session_state.filter_levels = selected_levels if selected_levels else all_levels
    
    with col_filter2:
        filter_conds = st.session_state.filter_conditions
        if filter_conds:
            cond_text = " + ".join([f"{c['column']}包含'{c['value']}'" for c in filter_conds if c.get('column') and c.get('value')])
            st.info(f"筛选: {cond_text}")
        else:
            st.info("未添加筛选条件")

    st.divider()
    st.caption("编辑筛选条件")

    available_cols = [col for col in df_marked.columns if col not in ['标记等级', '标记图标', '标记说明', '基础等级', '基础图标', '基础说明']]
    filter_conds = st.session_state.filter_conditions

    with st.form(key="filter_editor_form"):
        for cond_idx, cond in enumerate(filter_conds):
            col_c1, col_c2, col_c3 = st.columns([2, 2, 0.5])
            with col_c1:
                col_name = st.selectbox(
                    "列名",
                    options=available_cols,
                    index=available_cols.index(cond.get('column', '')) if cond.get('column', '') in available_cols else 0,
                    key=f"filter_col_{cond_idx}",
                    label_visibility="collapsed"
                )
                filter_conds[cond_idx]['column'] = col_name
            with col_c2:
                val = st.text_input(
                    "匹配值",
                    value=cond.get('value', ''),
                    key=f"filter_val_{cond_idx}",
                    label_visibility="collapsed"
                )
                filter_conds[cond_idx]['value'] = val
            with col_c3:
                if st.form_submit_button("✖️", key=f"remove_filter_{cond_idx}"):
                    st.session_state.filter_conditions.pop(cond_idx)
                    st.rerun()
        
        col_add1, col_add2 = st.columns([1, 3])
        with col_add1:
            if st.form_submit_button("➕ 添加筛选", use_container_width=True):
                st.session_state.filter_conditions.append({"column": "", "value": ""})
                st.rerun()
        with col_add2:
            st.caption(f"共 {len(st.session_state.filter_conditions)} 个筛选")
        
        if st.form_submit_button("🔍 应用筛选", use_container_width=False):
            st.rerun()
    
    filtered_df = df_marked.copy()
    filtered_df = filtered_df[filtered_df['标记等级'].isin(st.session_state.filter_levels)]
    for cond in filter_conds:
        col_name = cond.get('column', '').strip()
        value = cond.get('value', '').strip()
        if col_name and value:
            filtered_df = filtered_df[filtered_df[col_name].astype(str).str.contains(value, case=False, na=False)]

    st.caption(f"显示 {len(filtered_df)} 条（共 {len(df_marked)} 条）")
    st.dataframe(filtered_df, use_container_width=True, height=400)

    # ---- 快速加白 ----
    st.divider()
    st.subheader("⚡ 快速加白")

    col1, col2 = st.columns([3, 1])
    with col1:
        row_num = st.number_input("行号", min_value=1, max_value=len(df_marked), step=1, key="whitelist_row_num")
        selected_row = df_marked.iloc[row_num - 1] if row_num else None
        if selected_row is not None:
            src_ip = str(selected_row.get('源IP', '')).strip()
            dst_ip = str(selected_row.get('目的IP', '')).strip()
            dst_port = str(selected_row.get('目的端口', '')).strip()
            attack_type = str(selected_row.get('攻击类型', ''))
            
            st.info(
                f"**选中**: 源IP={src_ip} | 目的IP={dst_ip} | 端口={dst_port} | {attack_type}"
            )
            
            editable_ip = st.text_input(
                "源IP匹配（留空匹配所有）",
                value=src_ip,
                key="quick_whitelist_ip"
            )
            editable_conditions = st.text_area(
                "条件列表（JSON格式，可留空）",
                value=json.dumps([
                    {"column": "目的IP", "value": dst_ip},
                    {"column": "目的端口", "value": dst_port}
                ] if dst_ip and dst_port else [], ensure_ascii=False, indent=2),
                height=120,
                key="quick_whitelist_conditions"
            )
    
    with col2:
        if st.button("➕ 加白", use_container_width=True):
            if selected_row is not None:
                ip = editable_ip.strip()
                if ip and not is_valid_ip_pattern(ip):
                    st.error(f"IP格式无效: '{ip}'")
                else:
                    try:
                        conds = json.loads(editable_conditions) if editable_conditions.strip() else []
                        valid_conds = [c for c in conds if c.get('column', '').strip() and c.get('value', '').strip()]
                    except json.JSONDecodeError:
                        st.error("JSON格式错误")
                        st.stop()
                    new_rule = {
                        "ip": ip,
                        "comment": f"从行{row_num}快速加白",
                        "conditions": valid_conds
                    }
                    rules = st.session_state.config.get('trusted_rules', [])
                    exists = any(
                        r.get('ip') == new_rule['ip'] and 
                        r.get('conditions') == new_rule['conditions']
                        for r in rules
                    )
                    if exists:
                        st.warning("规则已存在")
                    else:
                        rules.append(new_rule)
                        update_rules_and_refresh(rules)
                        st.stop()
            else:
                st.error("请先选择行号")

    st.caption(f"共 {len(st.session_state.config.get('trusted_rules', []))} 条规则")

    # ---- 导出 ----
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df_marked.to_excel(writer, index=False, sheet_name='分析结果')
    st.download_button(
        label="📥 下载结果",
        data=output.getvalue(),
        file_name="firewall_analysis.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

else:
    st.info("👈 请上传日志文件")