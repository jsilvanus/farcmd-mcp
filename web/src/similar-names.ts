/**
 * Warnings for command names that are easy to confuse. An MCP client picks a command by name and description,
 * so "cok_coffee" next to "cook_coffee" (or a name spelled with look-alike Unicode letters) can make a client,
 * or the person, pick the wrong one. These are warnings only; nothing is refused.
 */
/** source: what the other name belongs to, an existing command or another pending suggestion. */
export type NameSource='command'|'suggestion';
export type NameWarning={kind:'duplicate'|'lookalike';name:string;source:NameSource}|{kind:'unicode'};

/** Lower case, digits that pass for letters mapped to them, and separators removed: "Cook_Coffee" -> "cookcoffee". */
export function normalizeName(name:string):string{
  return name.normalize('NFKC').toLowerCase()
    .replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/5/g,'s').replace(/\|/g,'l')
    .replace(/[\s_\-.:/\\,;·]+/g,'');
}

/** Optimal string alignment distance (Levenshtein plus swapping two neighbours). */
export function editDistance(a:string,b:string):number{
  const d:number[][]=Array.from({length:a.length+1},(_,i)=>[i,...new Array(b.length).fill(0)]);
  for(let j=1;j<=b.length;j++)d[0]![j]=j;
  for(let i=1;i<=a.length;i++)for(let j=1;j<=b.length;j++){
    const cost=a[i-1]===b[j-1]?0:1;
    let v=Math.min(d[i-1]![j]!+1,d[i]![j-1]!+1,d[i-1]![j-1]!+cost);
    if(i>1&&j>1&&a[i-1]===b[j-2]&&a[i-2]===b[j-1])v=Math.min(v,d[i-2]![j-2]!+1);
    d[i]![j]=v;
  }
  return d[a.length]![b.length]!;
}

/** Jaro similarity: 1 for equal strings, 0 for nothing in common. */
export function jaro(a:string,b:string):number{
  if(a===b)return 1; if(!a.length||!b.length)return 0;
  const window=Math.max(0,Math.floor(Math.max(a.length,b.length)/2)-1);
  const matchedA=new Array<boolean>(a.length).fill(false), matchedB=new Array<boolean>(b.length).fill(false);
  let matches=0;
  for(let i=0;i<a.length;i++)for(let j=Math.max(0,i-window);j<Math.min(b.length,i+window+1);j++){
    if(matchedB[j]||a[i]!==b[j])continue; matchedA[i]=matchedB[j]=true; matches++; break;
  }
  if(!matches)return 0;
  let transpositions=0,k=0;
  for(let i=0;i<a.length;i++){if(!matchedA[i])continue;while(!matchedB[k])k++;if(a[i]!==b[k])transpositions++;k++;}
  return (matches/a.length+matches/b.length+(matches-transpositions/2)/matches)/3;
}
/** Jaro-Winkler: Jaro with a bonus for a common start (up to 4 characters, scaling factor 0.1). */
export function jaroWinkler(a:string,b:string):number{
  const j=jaro(a,b); let prefix=0;
  while(prefix<4&&prefix<a.length&&prefix<b.length&&a[prefix]===b[prefix])prefix++;
  return j+prefix*0.1*(1-j);
}
const words=(name:string)=>name.normalize('NFKC').toLowerCase().split(/[\s_\-.:/\\,;·]+/).filter(Boolean);
/**
 * The parts of two names after the words they share at the start, normalized: "saarnavideo: stop" and
 * "saarnavideo: redeploy" -> "stop", "redeploy". Jaro-Winkler rewards a common start, so on whole names every
 * pair of commands in one family ("app: stop", "app: delete") would look alike; on the tails it does not.
 */
export function nameTails(a:string,b:string):[string,string]{
  const x=words(a),y=words(b); let i=0; while(i<x.length&&i<y.length&&x[i]===y[i])i++;
  return [normalizeName(x.slice(i).join('')),normalizeName(y.slice(i).join(''))];
}
/** Jaro-Winkler score of the tails at or above which two names count as look-alikes. */
export const JARO_WINKLER_THRESHOLD=0.9;

/** Characters outside printable ASCII: Cyrillic "а" or Greek "ο" look like Latin letters. */
export function hasNonAsciiLetters(name:string):boolean{return /[^\x20-\x7e]/.test(name);}

/**
 * Existing names that the given name duplicates or closely resembles. Two measures, either one is enough:
 * - edit distance of the normalized names: short names allow no typo, 4–11 characters one edit, longer two;
 * - Jaro-Winkler of the name tails (see nameTails) at least 0.9, when both tails have 3 or more characters.
 */
export function nameWarnings(name:string,existing:{id:string;name:string;source?:NameSource}[],ownId?:string):NameWarning[]{
  const trimmed=name.trim(); if(!trimmed)return [];
  const n=normalizeName(trimmed); const allowed=n.length>=12?2:n.length>=4?1:0;
  const warnings:NameWarning[]=[];
  for(const e of existing){
    if(e.id===ownId)continue;
    const source=e.source??'command';
    if(e.name.trim().toLowerCase()===trimmed.toLowerCase()){warnings.push({kind:'duplicate',name:e.name,source});continue;}
    const m=normalizeName(e.name); const [p,q]=nameTails(trimmed,e.name);
    if(m===n||editDistance(n,m)<=allowed||(Math.min(p.length,q.length)>=3&&jaroWinkler(p,q)>=JARO_WINKLER_THRESHOLD))warnings.push({kind:'lookalike',name:e.name,source});
  }
  if(hasNonAsciiLetters(trimmed))warnings.push({kind:'unicode'});
  return warnings;
}

export function describeNameWarning(w:NameWarning):string{
  const other=w.kind==='unicode'?'':w.source==='suggestion'?'the pending suggestion "'+w.name+'"':'the existing command "'+w.name+'"';
  if(w.kind==='duplicate')return 'Same name as '+other+'.';
  if(w.kind==='lookalike')return 'Looks like '+other+'. MCP clients and people can mistake one for the other.';
  return 'The name contains non-ASCII characters, which can look like ordinary letters (e.g. Cyrillic "а" for "a").';
}
