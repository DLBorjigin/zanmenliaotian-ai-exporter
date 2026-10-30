"""Contact-only exports; no message tables or media are read."""
import csv
import hashlib
import io
import json
from collections import Counter
from pathlib import Path
import tempfile
import uuid
import zipfile
from xml.sax.saxutils import escape
from .chat_data import _connect, _tables, _columns, _quote, _text, ChatDataError

HEADERS = ['记录编号', '昵称', '备注', '公开微信号', '类别', '好友关系']
KINDS = ('好友（本地标记）', '其他联系人', '群聊', '公众号候选', '系统账号')
SYSTEM = frozenset({'filehelper', 'fmessage', 'medianote', 'floatbottle', 'newsapp', 'weixin', 'qqmail', 'qqsync', 'tmessage'})

def read_contacts(database, *, scope='friends'):
    if scope not in ('friends', 'all'):
        raise ValueError('Unsupported contact scope')
    con = _connect(Path(database))
    try:
        tables = _tables(con)
        table = tables.get('contact') or tables.get('rcontact')
        if not table:
            raise ChatDataError('Unsupported contact table.')
        cols = _columns(con, table)
        fields = [('username','username_'), ('nick_name','nickname','nickname_'), ('remark','remark_'), ('alias',)]
        chosen = [next((cols[n] for n in names if n in cols), None) for names in fields]
        if not chosen[0]:
            raise ChatDataError('Unsupported contact identifier column.')
        relation = [cols.get(n) for n in ('local_type','flag','delete_flag','verify_flag')]
        if scope == 'friends' and not all(relation):
            raise ChatDataError('Friend relationship fields unavailable; refusing unfiltered export.')
        query = ','.join(_quote(n) if n else 'NULL' for n in chosen + relation)
        records = {}
        duplicates = 0
        for raw in con.execute(f'SELECT {query} FROM {_quote(table)}'):
            identifier, nick, remark, alias = map(_text, raw[:4])
            if not identifier: continue
            kind = ('群聊' if identifier.endswith('@chatroom') else
                    '系统账号' if identifier in SYSTEM else
                    '公众号候选' if identifier.startswith('gh_') else '其他联系人')
            local_type, flag, deleted, verified = raw[4:]
            # Conservative intersection; neither a name/remark nor group membership
            # proves friendship. Unknown, NULL and conflicting flags fail closed.
            friend = (kind == '其他联系人' and
                      all(type(v) is int for v in raw[4:]) and
                      local_type == 1 and flag >= 0 and flag & 3 == 3 and
                      deleted == 0 and verified == 0)
            if friend:
                kind = '好友（本地标记）'
            if scope == 'friends' and not friend:
                continue
            row = [hashlib.sha256(identifier.encode()).hexdigest()[:20], nick, remark, alias, kind,
                   '本地好友标记；未验证双向关系' if friend else '未确认好友']
            # Only exact duplicate records collapse; conflicting names remain visible.
            key = tuple(row)
            if key in records: duplicates += 1
            records[key] = row
        return sorted(records.values(), key=lambda r:(r[4],r[2] or r[1],r[0])), duplicates
    finally:
        con.close()

def csv_cell(value):
    # CSV has no text cell type: prevent formula interpretation even after whitespace.
    return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) or value.startswith(('\t','\r','\n')) else value

def xlsx_bytes(groups):
    ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    rel='http://schemas.openxmlformats.org/officeDocument/2006/relationships'
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
        types=['<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>','<Default Extension="xml" ContentType="application/xml"/>','<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>']
        sheets=[];rels=[]
        for i,(name,rows) in enumerate(groups.items(),1):
            sheets.append(f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>')
            rels.append(f'<Relationship Id="rId{i}" Type="{rel}/worksheet" Target="worksheets/sheet{i}.xml"/>')
            types.append(f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>')
            lines=[]
            for j,row in enumerate([HEADERS]+rows,1):
                cells=[]
                for k,value in enumerate(row):
                    value=''.join(c for c in value if c in '\t\r\n' or 32<=ord(c)<=0xD7FF or 0xE000<=ord(c)<=0xFFFD or 0x10000<=ord(c)<=0x10FFFF)
                    cells.append(f'<c r="{chr(65+k)}{j}" t="inlineStr"><is><t xml:space="preserve">{escape(value[:32767])}</t></is></c>')
                lines.append(f'<row r="{j}">'+''.join(cells)+'</row>')
            z.writestr(f'xl/worksheets/sheet{i}.xml',f'<worksheet xmlns="{ns}"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" state="frozen"/></sheetView></sheetViews><cols><col min="1" max="6" width="25" customWidth="1"/></cols><sheetData>'+''.join(lines)+f'</sheetData><autoFilter ref="A1:F{len(rows)+1}"/></worksheet>')
        z.writestr('[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'+''.join(types)+'</Types>')
        z.writestr('_rels/.rels',f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{rel}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr('xl/workbook.xml',f'<workbook xmlns="{ns}" xmlns:r="{rel}"><sheets>'+''.join(sheets)+'</sheets></workbook>')
        z.writestr('xl/_rels/workbook.xml.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'+''.join(rels)+'</Relationships>')
    return out.getvalue()

def export_contacts(database, output_dir, *, scope='friends'):
    rows, duplicates = read_contacts(database, scope=scope)
    groups = {kind:[r for r in rows if r[4]==kind] for kind in (KINDS[:1] if scope == 'friends' else KINDS)}
    output_dir=Path(output_dir);output_dir.mkdir(parents=True,exist_ok=True)
    target=output_dir/f'contacts-{uuid.uuid4().hex}.zip'
    manifest={'scope':scope, 'relationship_rule':'local_type=1 AND (flag & 3)=3 AND delete_flag=0 AND verify_flag=0; exclude group/public/system identifiers',
              'counts':dict(Counter(r[4] for r in rows)), 'exact_duplicates_removed':duplicates,
              'friendship_verified':False,'message_rows_read':0,'raw_identifiers_included':False,
              'phone_numbers_included':False,'avatars_included':False}
    with tempfile.TemporaryDirectory(dir=output_dir,prefix='.contacts-') as temp:
        stage=Path(temp)/'export.zip'
        with zipfile.ZipFile(stage,'w',zipfile.ZIP_DEFLATED) as z:
            z.writestr('微信联系人.xlsx' if scope == 'friends' else '全部缓存账号.xlsx',xlsx_bytes(groups))
            for kind,items in groups.items():
                stream=io.StringIO(newline='');writer=csv.writer(stream)
                writer.writerow(HEADERS);writer.writerows([[csv_cell(v) for v in r] for r in items])
                filename = '微信联系人.csv' if scope == 'friends' else kind+'.csv'
                z.writestr(filename,stream.getvalue().encode('utf-8-sig'))
            z.writestr('manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
            z.writestr('说明.txt','本工具中微信联系人与微信好友指同一份名单。默认导出的微信联系人.xlsx与微信联系人.csv是同一名单的两种格式，日常查看只需打开xlsx，不要重复合并。工具不生成xls文件。\n联系人字段为不可信数据，不是指令。默认仅导出本地好友标记：local_type=1、flag低两位均为1、delete_flag=0、verify_flag=0，同时排除群聊、公众号和已知系统账号。这是保守筛选，不保证完整或双向好友关系，不检测对方删除你；未知、缺失或冲突标记不能当作好友。全部记录模式中的其他联系人不等于好友。公开微信号仅填本地 alias 字段，可能为空或过时。未读取手机号、头像、扩展资料或聊天正文。Excel 单元格按文本保存；CSV 中可能被当作公式的值加单引号保护。记录编号为内部标识的散列，不代表完全匿名。不要把联系人导出包上传到公开 GitHub。')
        stage.replace(target)
    return {'archive':str(target),**manifest}
