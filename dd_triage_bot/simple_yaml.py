from __future__ import annotations
import ast

def _val(s: str):
    s=s.strip()
    if s in ('true','True'): return True
    if s in ('false','False'): return False
    if s in ('null','None',''): return None
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    if s.startswith('[') and s.endswith(']'):
        inner=s[1:-1].strip()
        if not inner: return []
        return [ _val(x.strip()) for x in inner.split(',') ]
    try: return int(s)
    except ValueError: return s

def safe_load(text: str):
    root={}; stack=[(-1, root)]
    lines=text.splitlines(); i=0
    while i < len(lines):
        raw=lines[i]; i+=1
        if not raw.strip() or raw.lstrip().startswith('#'): continue
        indent=len(raw)-len(raw.lstrip()); line=raw.strip()
        while stack and indent <= stack[-1][0]: stack.pop()
        parent=stack[-1][1]
        if line.startswith('- '):
            item=line[2:]
            if not isinstance(parent, list): continue
            if ':' in item:
                k,v=item.split(':',1); d={k.strip(): _val(v)} if v.strip() else {k.strip(): {}}
                parent.append(d); stack.append((indent,d if v.strip() else d[k.strip()]))
            else: parent.append(_val(item))
            continue
        k,v=line.split(':',1); k=k.strip(); v=v.strip()
        if v:
            parent[k]=_val(v)
        else:
            # lookahead decides list or dict
            nxt=''
            for j in range(i,len(lines)):
                if lines[j].strip() and not lines[j].lstrip().startswith('#'):
                    nxt=lines[j].strip(); break
            parent[k]=[] if nxt.startswith('- ') else {}
            stack.append((indent,parent[k]))
    return root
