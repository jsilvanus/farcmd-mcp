/**
 * Line diff between a command's current script and a proposed new version (longest common subsequence).
 * Lines shared at the start and end are matched first, so a small change in a long script stays cheap.
 */
export type DiffLine={op:' '|'+'|'-';text:string};
export interface LineDiff { lines:DiffLine[]; added:number; removed:number; }

/** Beyond this many cells (changed lines x changed lines) the diff is not computed; callers show both versions. */
export const MAX_DIFF_CELLS=4_000_000;

export function lineDiff(before:string,after:string):LineDiff|undefined{
  const a=before.split('\n'), b=after.split('\n');
  let start=0; while(start<a.length&&start<b.length&&a[start]===b[start])start++;
  let endA=a.length, endB=b.length; while(endA>start&&endB>start&&a[endA-1]===b[endB-1]){endA--;endB--;}
  const x=a.slice(start,endA), y=b.slice(start,endB);
  if(x.length*y.length>MAX_DIFF_CELLS)return undefined;
  // lcs[i][j] = length of the LCS of x[i..] and y[j..], one row per line of x.
  const lcs=Array.from({length:x.length+1},()=>new Uint32Array(y.length+1));
  for(let i=x.length-1;i>=0;i--)for(let j=y.length-1;j>=0;j--)lcs[i]![j]=x[i]===y[j]?lcs[i+1]![j+1]!+1:Math.max(lcs[i+1]![j]!,lcs[i]![j+1]!);
  const lines:DiffLine[]=a.slice(0,start).map(text=>({op:' ',text}));
  let i=0,j=0,added=0,removed=0;
  while(i<x.length||j<y.length){
    if(i<x.length&&j<y.length&&x[i]===y[j]){lines.push({op:' ',text:x[i]!});i++;j++;}
    else if(j<y.length&&(i===x.length||lcs[i]![j+1]!>=lcs[i+1]![j]!)){lines.push({op:'+',text:y[j]!});j++;added++;}
    else{lines.push({op:'-',text:x[i]!});i++;removed++;}
  }
  for(const text of a.slice(endA))lines.push({op:' ',text});
  return {lines,added,removed};
}

/** Unified-style text: "+ line", "- line", "  line". */
export function diffText(d:LineDiff):string{return d.lines.map(l=>l.op+' '+l.text).join('\n');}
