import test from 'node:test';
import assert from 'node:assert/strict';
import { describeNameWarning, editDistance, jaro, jaroWinkler, nameTails, nameWarnings, normalizeName } from '../web/src/similar-names.js';

const EXISTING=[{id:'1',name:'cook_coffee'},{id:'2',name:'saarnavideo: redeploy'},{id:'3',name:'df'}];
const kinds=(name:string,ownId?:string)=>nameWarnings(name,EXISTING,ownId).map(w=>w.kind+('name' in w?':'+w.name:''));

test('look-alike names are flagged: typos, swapped letters, separators, case and digits for letters',()=>{
  for(const name of ['cok_coffee','cooke_coffee','ccok_coffee','cook-coffee','Cook Coffee','c00k_coffee','cookcoffe'])
    assert.deepEqual(kinds(name),['lookalike:cook_coffee'],name);
  assert.deepEqual(kinds('coko_coffee'),['lookalike:cook_coffee'],'two neighbours swapped count as one edit');
  assert.deepEqual(kinds('saarnavide0: redeploy'),['lookalike:saarnavideo: redeploy']);
  assert.deepEqual(kinds('saarnavdeo: redepoy'),['lookalike:saarnavideo: redeploy'],'long names allow two edits');
});

test('exact duplicates, non-ASCII look-alike letters and nothing for clearly different names',()=>{
  assert.deepEqual(kinds('COOK_COFFEE'),['duplicate:cook_coffee']);
  assert.deepEqual(kinds('сook_coffee'),['lookalike:cook_coffee','unicode'],'Cyrillic с');
  assert.deepEqual(kinds('sermonize: redeploy'),[]);
  assert.deepEqual(kinds('cook_tea'),[]);
  assert.deepEqual(kinds('du'),[],'short names must match exactly: df and du are different commands');
  assert.deepEqual(kinds('cook_coffee','1'),[],'a command is not compared with itself');
  assert.deepEqual(kinds('  '),[]);
});

test('helpers',()=>{
  assert.equal(normalizeName('Cook_Coffee 1'),'cookcoffeel');
  assert.equal(editDistance('kitten','sitting'),3);
  assert.equal(editDistance('ab','ba'),1);
});

test('Jaro-Winkler on the name tails: typos in a family are flagged, siblings are not',()=>{
  const family=[{id:'a',name:'saarnavideo: redeploy'},{id:'b',name:'saarnavideo: stop'},{id:'c',name:'service status'},{id:'d',name:'restart_backend'}];
  const flagged=(name:string)=>nameWarnings(name,family).filter(w=>w.kind==='lookalike').map(w=>'name' in w?w.name:'');
  assert.deepEqual(flagged('saarnavideo: redepoly'),['saarnavideo: redeploy'],'transposed letters');
  assert.deepEqual(flagged('restart_backnd'),['restart_backend']);
  for(const name of ['saarnavideo: delete','saarnavideo: nginx','service start','restart_frontend','sermonize: redeploy'])
    assert.deepEqual(flagged(name),[],name+' is a different command');
  assert.deepEqual(nameTails('saarnavideo: stop','saarnavideo: redeploy'),['stop','redeploy']);
});

test('warnings say whether the look-alike is a command or another pending suggestion',()=>{
  const w=nameWarnings('cok_coffee',[{id:'1',name:'cook_coffee',source:'suggestion'}]);
  assert.deepEqual(w,[{kind:'lookalike',name:'cook_coffee',source:'suggestion'}]);
});

test('pending suggestions warn about each other, never about themselves',()=>{
  const pool=[{id:'c1',name:'cook_coffee',source:'command' as const},{id:'s1',name:'cok_coffee',source:'suggestion' as const},{id:'s2',name:'cok_cofee',source:'suggestion' as const},{id:'s3',name:'restart_backend',source:'suggestion' as const}];
  const others=(id:string)=>{const own=pool.find(e=>e.id===id)!;return nameWarnings(own.name,pool,id).map(w=>'name' in w?w.source+':'+w.name:w.kind);};
  assert.deepEqual(others('s1'),['command:cook_coffee','suggestion:cok_cofee']);
  assert.deepEqual(others('s2'),['suggestion:cok_coffee'],'two typos away from the command, one from the other suggestion');
  assert.deepEqual(others('c1'),['suggestion:cok_coffee'],'the command is warned about the suggestion too');
  assert.deepEqual(others('s3'),[]);
  // Two suggestions with the same name: a duplicate of each other, but each skips its own entry.
  const twins=[{id:'a',name:'deploy',source:'suggestion' as const},{id:'b',name:'Deploy',source:'suggestion' as const}];
  assert.deepEqual(nameWarnings('deploy',twins,'a'),[{kind:'duplicate',name:'Deploy',source:'suggestion'}]);
});

test('describeNameWarning names the other entry and its source',()=>{
  assert.equal(describeNameWarning({kind:'duplicate',name:'cook_coffee',source:'command'}),'Same name as the existing command "cook_coffee".');
  assert.equal(describeNameWarning({kind:'lookalike',name:'cok_coffee',source:'suggestion'}),'Looks like the pending suggestion "cok_coffee". MCP clients and people can mistake one for the other.');
  assert.equal(describeNameWarning({kind:'lookalike',name:'cook_coffee',source:'command'}),'Looks like the existing command "cook_coffee". MCP clients and people can mistake one for the other.');
  assert.match(describeNameWarning({kind:'unicode'}),/non-ASCII characters/);
});

test('Jaro and Jaro-Winkler reference values',()=>{
  assert.equal(jaro('martha','marhta').toFixed(3),'0.944'); assert.equal(jaroWinkler('martha','marhta').toFixed(3),'0.961');
  assert.equal(jaroWinkler('dixon','dicksonx').toFixed(3),'0.813');
  assert.equal(jaro('abc','abc'),1); assert.equal(jaro('abc',''),0);
});
