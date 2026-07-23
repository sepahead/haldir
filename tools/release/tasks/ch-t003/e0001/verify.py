#!/usr/bin/env python3
# ruff: noqa: E701, E702, F401
# fmt: off
'Verify the signed CH-T003 public-surface inventory lifecycle.'
from __future__ import annotations
import argparse
import ast
import base64
import binascii
import csv
import copy
import hashlib
import io
import json
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import unicodedata
import urllib.parse
import zipfile
import zlib
from datetime import datetime,timezone
from pathlib import Path,PurePosixPath
from typing import Any
TASK_ID='CH-T003'
EPOCH=1
RELEASE_TARGET='0.9.0'
AUTHOR={'name':'Sepehr Mahmoudian','email':'sepmhn@gmail.com'}
PROHIBITED_GOVERNANCE_TOKEN=b'super'+b'visor'
SECRET_OUTPUT_PATTERNS=re.compile(b'github_pat_[A-Za-z0-9_]{20,}',re.IGNORECASE),re.compile(b'gh[oprsu]_[A-Za-z0-9]{20,}',re.IGNORECASE),re.compile(b'sk-ant-[A-Za-z0-9_-]{10,}',re.IGNORECASE),re.compile(b'-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|PGP [A-Z0-9 ]*KEY BLOCK)-----',re.IGNORECASE)
ANSI_SGR=re.compile(b'\\x1b\\[[0-9]{1,3}(?:;[0-9]{1,3}){0,8}m')
OUTCOME_ID='CH-T003-O01-PUBLIC-CLAIM-NARROWED'
NARROWED_CLAIM='CL-PUBLICATION-EVIDENCE-PRIMITIVE-01'
NARROWED_CLAIM_STATEMENT='Repository VERIFIED evidence primitives do not establish VALIDATED, DEPLOYMENT_QUALIFIED, or FIELD_VALIDATED status, a release-qualified artifact, transport delivery, or operational use.'
PRIOR_ACTIVATION='590ba767b32a27d9dd61a2462968306c1052434e'
PRIOR_FREEZE='b737cfa85d03c377be269498a2209ca873c3f906'
PRIOR_IMPLEMENTATION='5f3d60c225c89ee05da11cecd1beaddd68f74ec8'
PRIOR_QUALIFICATION='7a4e3f7d79ba5561ab961e374c4c38dbbd9d0f1b'
PRIOR_ACTIVATION_TREE='9b95208eb7a1aed59e00e824b277851bb10de229'
DATA_ROOT='release/0.9.0/current-head/tasks/ch-t003/e0001'
FREEZE_PATH=f"{DATA_ROOT}/freeze.json"
QUALIFICATION_PATH=f"{DATA_ROOT}/qualification.json"
ACTIVATION_PATH=f"{DATA_ROOT}/activation.json"
RECEIPT_PATH=f"{DATA_ROOT}/verifier-receipt.json"
VERIFIER_PATH='tools/release/tasks/ch-t003/e0001/verify.py'
TESTS_PATH='tools/release/tasks/ch-t003/e0001/test_verify.py'
REGISTRY_PATH='release/0.9.0/current-head/closures/task-verifier-registry.json'
REQUIREMENTS_PATH='release/0.9.0/current-head/requirements.json'
CLAIMS_STATE_PATH='release/0.9.0/current-head/closures/active-claims.json'
CLAIM_LEDGER_PATH='docs/CLAIM-LEDGER.md'
PUBLIC_INVENTORY_PATH='audit/generated/CH-T003_PUBLIC_SURFACE_INVENTORY.json'
CLAIM_TIER_PATH='audit/generated/CH-T003_CLAIM_TIER_LEDGER.json'
REVIEW_OVERLAY_PATH='audit/generated/CH-T003_FILE_REVIEW_OVERLAY.json'
LEDGER_COMPOSITION_PATH='audit/generated/CH-T003_LEDGER_COMPOSITION.json'
GITHUB_METADATA_PATH='audit/generated/CH-T003_GITHUB_METADATA.json'
CLAIM_LANGUAGE_PATH='audit/generated/CLAIM_LANGUAGE.json'
PRODUCT_PATH='tools/release/current-public-surface-inventory.py'
PRODUCT_TESTS_PATH='tools/release/test_current_public_surface_inventory.py'
GIT_EXECUTABLE='/usr/bin/git'
SSH_KEYGEN_EXECUTABLE='/usr/bin/ssh-keygen'
EVIDENCE_ROOT=f"{DATA_ROOT}/evidence"
REVIEW_ROOT=f"{DATA_ROOT}/reviews"
ACTIVATION_EVIDENCE_ROOT=f"{DATA_ROOT}/activation-evidence"
EVIDENCE_SPECS=('CH-T003-E01','FILE_REVIEW_TRACEABILITY','file-review-traceability.json','haldir.ch-t003.file-review-traceability.v1'),('CH-T003-E02','COMPLETE_COMMAND_LOG','complete-command-log.json','haldir.ch-t003.complete-command-log.v1'),('CH-T003-E03','POSITIVE_NEGATIVE_VECTORS','positive-negative-vectors.json','haldir.ch-t003.positive-negative-vectors.v1'),('CH-T003-E04','COVERAGE_FUZZ_MUTATION_MODEL','coverage-fuzz-mutation-model.json','haldir.ch-t003.coverage-fuzz-mutation-model.v1'),('CH-T003-E05','RESOURCE_TIME_MAXIMA','resource-time-maxima.json','haldir.ch-t003.resource-time-maxima.v1'),('CH-T003-E06','EXACT_IDENTITIES_CHECKSUMS','exact-identities-checksums.json','haldir.ch-t003.exact-identities-checksums.v1'),('CH-T003-E07','CLAIM_MIGRATION_DISPOSITION','claim-migration-disposition.json','haldir.ch-t003.claim-migration-disposition.v1'),('CH-T003-E08','COMPLETE_REVIEWED_ASSIGNED_FILE_LEDGER','complete-reviewed-assigned-file-ledger.json','haldir.ch-t003.complete-reviewed-assigned-file-ledger.v1'),('CH-T003-E09','PUBLIC_SURFACE_INVENTORY','public-surface-inventory.json','haldir.ch-t003.public-surface-inventory-evidence.v1'),('CH-T003-E10','CLAIM_TIER_LEDGER','claim-tier-ledger.json','haldir.ch-t003.claim-tier-ledger-evidence.v1'),('CH-T003-E11','GITHUB_METADATA_CAPTURE','github-metadata-capture.json','haldir.ch-t003.github-metadata-capture-evidence.v1'),('CH-T003-E12','POST_IMPLEMENTATION_GITHUB_HEAD_CAPTURE','post-implementation-github-head-capture.json','haldir.ch-t003.post-implementation-github-head-capture.v1'),('CH-T003-E13','COMPILER_RESOLVED_RUST_API','compiler-resolved-rust-api.json','haldir.ch-t003.compiler-resolved-rust-api.v1')
EVIDENCE_PATHS={identifier:f"{EVIDENCE_ROOT}/{name}"for(identifier,_kind,name,_schema)in EVIDENCE_SPECS}
REVIEW_SPECS=('CH-T003-R01','INDEPENDENT_REVIEW','lane-01-independent-review.json'),('CH-T003-R02','INDEPENDENT_REVIEW_LANE_02','lane-02-independent-review.json'),('CH-T003-R03','INDEPENDENT_REVIEW_LANE_03','lane-03-independent-review.json'),('CH-T003-R04','LEAD_IMPLEMENTATION_REVIEW','lead-implementation-review.json')
REVIEW_PATHS={identifier:f"{REVIEW_ROOT}/{name}"for(identifier,_kind,name)in REVIEW_SPECS}
ACTIVATION_SPECS=('CH-T003-A01','SUBSYSTEM_GATE','subsystem-gate.json','haldir.ch-t003.subsystem-gate.v1'),('CH-T003-A02','WAVE_GATE','wave-gate.json','haldir.ch-t003.wave-gate.v2'),('CH-T003-A03','FULL_LOCKED_CI','full-locked-ci.json','haldir.ch-t003.full-locked-ci.v3'),('CH-T003-A04','DOWNSTREAM_CONFORMANCE_DISPOSITION','downstream-conformance-disposition.json','haldir.ch-t003.downstream-conformance-disposition.v1'),('CH-T003-A05','FULL_LOCKED_CI_LOG_ARCHIVE','full-locked-ci-attempt-logs.zip',None)
ACTIVATION_PATHS={identifier:f"{ACTIVATION_EVIDENCE_ROOT}/{name}"for(identifier,_kind,name,_schema)in ACTIVATION_SPECS}
IMPLEMENTATION_PLAN={CLAIM_TIER_PATH:'A',REVIEW_OVERLAY_PATH:'A',GITHUB_METADATA_PATH:'A',LEDGER_COMPOSITION_PATH:'A',PUBLIC_INVENTORY_PATH:'A',CLAIM_LANGUAGE_PATH:'A',CLAIM_LEDGER_PATH:'M',PRODUCT_PATH:'A',PRODUCT_TESTS_PATH:'A'}
EXPECTED_SUBJECTS={'F':'release: freeze CH-T003 verification protocol','I':'release: implement CH-T003 public-surface inventory','C':'release: qualify CH-T003 public-surface inventory','D':'release: activate CH-T003 public-surface inventory'}
PUBLIC_CLASSIFICATIONS={'BUILD_OR_DEPLOYMENT','PUBLIC_API_OR_SCHEMA','PUBLIC_DOCUMENTATION'}
CLAIM_STATUSES={'PROVEN','PARTIAL','PENDING','UNPROVEN','OUT OF SCOPE','REMOVED','NOT_CLAIMED'}
TIER_VOCABULARY='IMPLEMENTED','VERIFIED','VALIDATED','DEPLOYMENT_QUALIFIED','FIELD_VALIDATED','NOT_CLAIMED'
TIER_BY_STATUS={'PROVEN':'VERIFIED','PARTIAL':'IMPLEMENTED','PENDING':'IMPLEMENTED','UNPROVEN':'NOT_CLAIMED','OUT OF SCOPE':'NOT_CLAIMED','REMOVED':'NOT_CLAIMED','NOT_CLAIMED':'NOT_CLAIMED'}
MINIMUM_EVIDENCE_BY_CLAIM_TYPE={'EVIDENCE_OR_PUBLICATION':['BOUND_SOURCE_ARTIFACT','REPRODUCIBLE_VERIFIER','NON_SUBSTITUTION_BOUNDARY'],'INTERFACE_OR_INTEROPERABILITY':['BOUND_INTERFACE_DEFINITION','CONFORMANCE_OR_NEGATIVE_TEST','VERSION_IDENTITY'],'FORMAL_OR_MODEL':['BOUND_MODEL','PINNED_CHECKER_RESULT','MODEL_TO_IMPLEMENTATION_LIMITATION'],'SECURITY_OR_AUTHORITY':['BOUND_IMPLEMENTATION','ADVERSARIAL_OR_NEGATIVE_TEST','EXPLICIT_ASSUMPTIONS'],'DEPLOYMENT_OR_RUNTIME':['BOUND_IMPLEMENTATION','RETAINED_RUNTIME_CAPTURE','DEPLOYMENT_IDENTITY'],'IMPLEMENTATION':['BOUND_IMPLEMENTATION','AUTOMATED_TEST_OR_STATIC_CHECK']}
NON_SUBSTITUTES_BY_CLAIM_TYPE={'EVIDENCE_OR_PUBLICATION':['DOCUMENTATION_ALONE','SELF_ASSERTION_ALONE','UNBOUND_LOG'],'INTERFACE_OR_INTEROPERABILITY':['SOURCE_SHAPE_WITHOUT_COMPILER_OR_PARSER','UNPINNED_UPSTREAM'],'FORMAL_OR_MODEL':['MODEL_RESULT_WITHOUT_REFINEMENT_BOUNDARY','FINITE_MODEL_AS_FIELD_VALIDATION'],'SECURITY_OR_AUTHORITY':['HAPPY_PATH_TEST_ONLY','CONFIGURATION_INTENT_AS_LIVE_ENFORCEMENT'],'DEPLOYMENT_OR_RUNTIME':['BUILDER_ONLY','CONFIGURATION_ONLY','SYNTHETIC_CAPTURE_AS_FIELD_EVIDENCE'],'IMPLEMENTATION':['DOCUMENTATION_ALONE','UNREVIEWED_EXAMPLE']}
BASELINE_CLAIM_TERMS='safe','secure','verified','validated','production-ready','production ready','field-tested','field tested','exact','identical','complete','correct','real-time','real time','certified','compatible','stable','proven','guarantee'
EXTENDED_CLAIM_TERMS='airworthy','complete mediation','deployment','exactly once','field validated','production','release-qualified','release qualified'
HIGH_RISK_TERMS=tuple(sorted(set(BASELINE_CLAIM_TERMS+EXTENDED_CLAIM_TERMS)))
BASELINE_CLAIM_REGEX=re.compile('(?i)\\b(?:safe|secure|verified|validated|production[- ]ready|field[- ]tested|exact|identical|complete|correct|real[- ]time|certified|compatible|stable|proven|guarantee)\\b')
EXTENDED_CLAIM_REGEX=re.compile('(?i)\\b(airworthy|certified|complete(?: mediation)?|correct|deployment|exact(?:ly once)?|field[- ](?:tested|validated)|guarantee|identical|production[- ]ready|proven|real[- ]time|release[- ]qualified|safe|secure|stable|validated|verified)\\b')
MAX_JSON_BYTES=4194304
MAX_GIT_BYTES=8388608
MAX_SNAPSHOT_BYTES=67108864
MAX_BLOB_BYTES=4194304
MAX_PATH_BYTES=240
MAX_TREE_ENTRIES=8192
MAX_CLAIMS=512
MAX_LANGUAGE_HITS=65536
MAX_ARCHIVE_MEMBERS=4096
MAX_ARCHIVE_MEMBER_BYTES=4194304
MAX_ARCHIVE_EXPANDED_BYTES=16777216
MAX_ARCHIVE_RATIO=100
NESTED_ARCHIVE_SUFFIXES='.7z','.bz2','.gz','.gzip','.rar','.tar','.tar.bz2','.tar.gz','.tar.xz','.tar.zst','.tbz','.tbz2','.tgz','.txz','.xz','.zip','.zst'
ARCHIVE_MAGIC_PREFIXES=b'PK\x03\x04',b'PK\x05\x06',b'\x1f\x8b\x08',b'BZh',b'\xfd7zXZ\x00',b"7z\xbc\xaf'\x1c",b'Rar!\x1a\x07',b'(\xb5/\xfd'
KNOWN_FILE_SUFFIXES={'.cfg','.cbor','.csv','.dockerignore','.gitignore','.gz','.hex','.ico','.json','.json5','.lock','.log','.md','.ncp-consumer','.pdf','.py','.proto','.rs','.rst','.sh','.sha256','.svg','.tla','.toml','.txt','.wasm','.yaml','.yml','.zip'}
KNOWN_EXTENSIONLESS_NAMES={'Dockerfile','LICENSE-APACHE','LICENSE-MIT','AUTHORS','COPYING','NOTICE','allowed-signers','justfile'}
CLAIM_PATTERN=re.compile('\\bCL-[A-Z0-9]+(?:-[A-Z0-9]+)+\\b')
PUBLIC_DECL_PATTERN=re.compile('^\\s*pub\\s+(?:async\\s+)?(?:unsafe\\s+)?(?:extern\\s+\\"[^\\"]+\\"\\s+)?(?:struct|enum|trait|fn|type|const|static|mod|use)\\b')
class VerifyError(RuntimeError):'A deterministic task-verification failure.'
def sha256(payload:bytes)->str:return hashlib.sha256(payload).hexdigest()
def canonical_json(value:Any)->bytes:return(json.dumps(value,ensure_ascii=False,allow_nan=False,sort_keys=True,separators=(',',':'))+'\n').encode('utf-8')
def reject_constant(value:str)->None:raise VerifyError(f"JSON_NONFINITE:{value}")
def reject_pairs(pairs:list[tuple[str,Any]])->dict[str,Any]:
	result:dict[str,Any]={}
	for(key,value)in pairs:
		if key in result:raise VerifyError(f"JSON_DUPLICATE_KEY:{key}")
		result[key]=value
	return result
def depth(value:Any,level:int=0)->int:
	if level>64:raise VerifyError('JSON_DEPTH')
	if isinstance(value,dict):return max((depth(item,level+1)for item in value.values()),default=level)
	if isinstance(value,list):return max((depth(item,level+1)for item in value),default=level)
	if isinstance(value,float)and not math.isfinite(value):raise VerifyError('JSON_NONFINITE')
	return level
def validate_unicode_scalars(value:Any)->None:
	if isinstance(value,str):
		if any(55296<=ord(character)<=57343 for character in value):raise VerifyError('JSON_UNICODE_SCALAR')
		return
	if isinstance(value,dict):
		for(key,item)in value.items():validate_unicode_scalars(key);validate_unicode_scalars(item)
		return
	if isinstance(value,list):
		for item in value:validate_unicode_scalars(item)
def load_json(payload:bytes,*,canonical:bool=True,maximum:int=MAX_JSON_BYTES)->Any:
	if not payload or len(payload)>maximum:raise VerifyError('JSON_SIZE')
	try:value=json.loads(payload.decode('utf-8'),object_pairs_hook=reject_pairs,parse_constant=reject_constant)
	except(UnicodeDecodeError,json.JSONDecodeError)as error:raise VerifyError('JSON_INVALID')from error
	depth(value);validate_unicode_scalars(value)
	if canonical and payload!=canonical_json(value):raise VerifyError('JSON_NOT_CANONICAL')
	return value
def valid_path(path:str)->bool:
	if not isinstance(path,str)or not path or len(path.encode('utf-8'))>MAX_PATH_BYTES:return False
	if path!=unicodedata.normalize('NFC',path)or'\\'in path or'\x00'in path:return False
	pure=PurePosixPath(path);return not pure.is_absolute()and all(part not in{'','.','..','.git'}for part in pure.parts)
def git_environment(repo:Path)->dict[str,str]:return{'GIT_ALLOW_PROTOCOL':'','GIT_ATTR_NOSYSTEM':'1','GIT_CONFIG_COUNT':'3','GIT_CONFIG_GLOBAL':'/dev/null','GIT_CONFIG_KEY_0':'safe.directory','GIT_CONFIG_VALUE_0':os.fspath(repo.resolve()),'GIT_CONFIG_KEY_1':'core.hooksPath','GIT_CONFIG_VALUE_1':'/dev/null','GIT_CONFIG_KEY_2':'core.fsmonitor','GIT_CONFIG_VALUE_2':'false','GIT_CONFIG_NOSYSTEM':'1','GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_TERMINAL_PROMPT':'0','HOME':'/nonexistent','LANG':'C','LC_ALL':'C','PATH':'/usr/bin:/bin'}
def run_bounded(arguments:list[str],*,repo:Path,timeout:int,maximum:int,input_payload:bytes|None=None)->subprocess.CompletedProcess[bytes]:
	input_file:io.BufferedRandom|None=None;process:subprocess.Popen[bytes]|None=None;stdout=bytearray();stderr=bytearray()
	try:
		if input_payload is not None:
			if len(input_payload)>MAX_SNAPSHOT_BYTES:raise VerifyError('PROCESS_INPUT_LIMIT')
			input_file=tempfile.TemporaryFile();input_file.write(input_payload);input_file.seek(0)
		process=subprocess.Popen(arguments,cwd=repo,env=git_environment(repo),stdin=input_file if input_file is not None else subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
		if process.stdout is None or process.stderr is None:raise VerifyError('PROCESS_PIPE')
		with selectors.DefaultSelector()as selector:
			selector.register(process.stdout,selectors.EVENT_READ,stdout);selector.register(process.stderr,selectors.EVENT_READ,stderr);deadline=time.monotonic()+timeout
			while selector.get_map():
				remaining=deadline-time.monotonic()
				if remaining<=0:raise subprocess.TimeoutExpired(arguments,timeout)
				events=selector.select(min(remaining,.25))
				if not events and process.poll()is not None:events=[(key,selectors.EVENT_READ)for key in tuple(selector.get_map().values())]
				for(key,_mask)in events:
					chunk=os.read(key.fd,65536)
					if not chunk:selector.unregister(key.fileobj);continue
					target=key.data;target.extend(chunk)
					if len(target)>maximum:raise VerifyError('PROCESS_OUTPUT_LIMIT')
		returncode=process.wait(timeout=max(.1,deadline-time.monotonic()))
		try:os.killpg(process.pid,signal.SIGKILL)
		except ProcessLookupError:pass
	except(OSError,subprocess.TimeoutExpired)as error:
		if process is not None:
			try:os.killpg(process.pid,signal.SIGKILL)
			except ProcessLookupError:pass
			process.wait()
		raise VerifyError('PROCESS_EXECUTION')from error
	except BaseException:
		if process is not None:
			try:os.killpg(process.pid,signal.SIGKILL)
			except ProcessLookupError:pass
			process.wait()
		raise
	finally:
		if process is not None:
			if process.stdout is not None:process.stdout.close()
			if process.stderr is not None:process.stderr.close()
		if input_file is not None:input_file.close()
	return subprocess.CompletedProcess(arguments,returncode,bytes(stdout),bytes(stderr))
def git(repo:Path,*arguments:str,maximum:int=MAX_GIT_BYTES)->bytes:
	command=[GIT_EXECUTABLE,'--no-replace-objects','--no-optional-locks','-c','core.pager=cat','-c','color.ui=false',*arguments];completed=run_bounded(command,repo=repo,timeout=5,maximum=maximum)
	if completed.returncode!=0 or completed.stderr:raise VerifyError('GIT_COMMAND')
	return completed.stdout
def git_text(repo:Path,*arguments:str)->str:
	try:return git(repo,*arguments).decode('utf-8').strip()
	except UnicodeDecodeError as error:raise VerifyError('GIT_UTF8')from error
def is_ancestor(repo:Path,ancestor:str,descendant:str)->bool:
	if re.fullmatch('[0-9a-f]{40}',ancestor)is None or re.fullmatch('[0-9a-f]{40}',descendant)is None:raise VerifyError('ANCESTOR_ARGUMENT')
	completed=run_bounded([GIT_EXECUTABLE,'--no-replace-objects','--no-optional-locks','-c','core.pager=cat','-c','color.ui=false','merge-base','--is-ancestor',ancestor,descendant],repo=repo,timeout=5,maximum=1024)
	if completed.stderr or completed.stdout or completed.returncode not in{0,1}:raise VerifyError('ANCESTOR_COMMAND')
	return completed.returncode==0
def git_file(repo:Path,commit:str,path:str,*,maximum:int=MAX_GIT_BYTES)->bytes:
	if re.fullmatch('[0-9a-f]{40}',commit)is None or not valid_path(path):raise VerifyError('GIT_FILE_ARGUMENT')
	return git(repo,'show',f"{commit}:{path}",maximum=maximum)
def commit_meta(repo:Path,commit:str)->dict[str,str]:
	fields=git(repo,'show','-s','--format=%H%x00%P%x00%T%x00%s%x00%an%x00%ae',commit).decode('utf-8').rstrip('\n').split('\x00')
	if len(fields)!=6 or fields[0]!=commit:raise VerifyError('COMMIT_METADATA')
	return{'commit':fields[0],'parents':fields[1],'tree':fields[2],'subject':fields[3],'author_name':fields[4],'author_email':fields[5]}
def verify_signature(repo:Path,commit:str)->None:
	allowed_payload=git_file(repo,PRIOR_ACTIVATION,'release/0.9.0/allowed-signers')
	if git_file(repo,commit,'release/0.9.0/allowed-signers')!=allowed_payload:raise VerifyError('ALLOWED_SIGNERS_DRIFT')
	if not allowed_payload or len(allowed_payload)>65536:raise VerifyError('ALLOWED_SIGNERS')
	try:
		with tempfile.NamedTemporaryFile(prefix='haldir-allowed-signers-')as handle:handle.write(allowed_payload);handle.flush();command=[GIT_EXECUTABLE,'--no-replace-objects','--no-optional-locks','-c','gpg.format=ssh','-c',f"gpg.ssh.allowedSignersFile={handle.name}",'-c',f"gpg.ssh.program={SSH_KEYGEN_EXECUTABLE}",'-c','gpg.ssh.revocationFile=/dev/null','-c','gpg.minTrustLevel=fully','verify-commit',commit];completed=run_bounded(command,repo=repo,timeout=5,maximum=65536)
	except(OSError,subprocess.TimeoutExpired)as error:raise VerifyError('COMMIT_SIGNATURE_EXECUTION')from error
	if completed.returncode!=0:raise VerifyError('COMMIT_SIGNATURE')
def changed_statuses(repo:Path,parent:str,commit:str)->dict[str,str]:
	raw=git(repo,'diff-tree','--no-commit-id','--name-status','-r','--no-renames','-z',parent,commit);fields=raw.split(b'\x00')
	if fields and fields[-1]==b'':fields.pop()
	if len(fields)%2:raise VerifyError('DIFF_FORMAT')
	result:dict[str,str]={}
	for index in range(0,len(fields),2):
		status=fields[index].decode('ascii');path=fields[index+1].decode('utf-8')
		if status not in{'A','M','D'}or not valid_path(path)or path in result:raise VerifyError('DIFF_STATUS')
		result[path]=status
	return dict(sorted(result.items()))
def tree_entries(repo:Path,commit:str)->list[dict[str,Any]]:
	raw=git(repo,'ls-tree','-r','-l','-z','--full-tree',commit);records:list[dict[str,Any]]=[]
	for item in raw.split(b'\x00'):
		if not item:continue
		try:header,path_bytes=item.split(b'\t',1);mode,object_type,object_id,size_text=header.decode('ascii').split();path=path_bytes.decode('utf-8');size=int(size_text)
		except(ValueError,UnicodeDecodeError)as error:raise VerifyError('TREE_FORMAT')from error
		if not valid_path(path):raise VerifyError('TREE_PATH')
		if object_type!='blob'or mode not in{'100644','100755'}:raise VerifyError('TREE_UNSUPPORTED_ENTRY')
		if size<0 or size>MAX_BLOB_BYTES:raise VerifyError('TREE_BLOB_CAPACITY')
		records.append({'path':path,'git_mode':mode,'git_object_type':object_type,'git_object_id':object_id,'git_object_bytes':size})
	if not records or len(records)>MAX_TREE_ENTRIES or[item['path']for item in records]!=sorted(item['path']for item in records):raise VerifyError('TREE_ORDER')
	return records
def targeted_tree_entry(repo:Path,commit:str,path:str)->dict[str,Any]:
	if re.fullmatch('[0-9a-f]{40}',commit)is None or not valid_path(path):raise VerifyError('TARGETED_TREE_ARGUMENT')
	raw=git(repo,'ls-tree','-l','-z','--full-tree',commit,'--',path,maximum=MAX_PATH_BYTES+256);items=[item for item in raw.split(b'\x00')if item]
	if len(items)!=1:raise VerifyError('TARGETED_TREE_CARDINALITY')
	try:header,path_bytes=items[0].split(b'\t',1);mode,object_type,object_id,size_text=header.decode('ascii').split();observed_path=path_bytes.decode('utf-8');size=int(size_text)
	except(ValueError,UnicodeDecodeError)as error:raise VerifyError('TARGETED_TREE_FORMAT')from error
	if observed_path!=path or mode not in{'100644','100755'}or object_type!='blob'or re.fullmatch('[0-9a-f]{40}',object_id)is None or not 0<=size<=MAX_BLOB_BYTES:raise VerifyError('TARGETED_TREE_ENTRY')
	return{'path':path,'git_mode':mode,'git_object_type':object_type,'git_object_id':object_id,'git_object_bytes':size}
def tree_snapshot(repo:Path,commit:str)->tuple[list[dict[str,Any]],dict[str,bytes]]:
	cache_key=os.fspath(repo.resolve()),commit;cached=_TREE_SNAPSHOT_CACHE.get(cache_key)
	if cached is not None:return cached
	entries=tree_entries(repo,commit);declared_total=0
	for entry in entries:
		declared_total+=entry['git_object_bytes']
		if declared_total>MAX_SNAPSHOT_BYTES:raise VerifyError('TREE_SNAPSHOT_CAPACITY')
	request=b''.join(item['git_object_id'].encode('ascii')+b'\n'for item in entries);completed=run_bounded([GIT_EXECUTABLE,'--no-replace-objects','--no-optional-locks','cat-file','--batch'],repo=repo,timeout=9,maximum=declared_total+len(entries)*128,input_payload=request)
	if completed.returncode!=0 or completed.stderr:raise VerifyError('CAT_FILE_COMMAND')
	output=completed.stdout;offset=0;blobs:dict[str,bytes]={}
	for entry in entries:
		newline=output.find(b'\n',offset)
		if newline<0:raise VerifyError('CAT_FILE_HEADER')
		header=output[offset:newline].split(b' ')
		if len(header)!=3 or header[0].decode('ascii')!=entry['git_object_id']or header[1]!=b'blob':raise VerifyError('CAT_FILE_HEADER')
		try:size=int(header[2])
		except ValueError as error:raise VerifyError('CAT_FILE_SIZE')from error
		start=newline+1;end=start+size
		if size!=entry['git_object_bytes']or end>=len(output)or output[end:end+1]!=b'\n':raise VerifyError('CAT_FILE_PAYLOAD')
		blobs[entry['path']]=output[start:end]
		if output[start:end].startswith(b'version https://git-lfs.github.com/spec/v1\n'):raise VerifyError('TREE_LFS_POINTER')
		offset=end+1
	if offset!=len(output)or len(blobs)!=len(entries):raise VerifyError('CAT_FILE_TRAILING')
	result=entries,blobs;_TREE_SNAPSHOT_CACHE[cache_key]=result;return result
def classify_path(path:str)->str|None:
	lowered=path.casefold();name=PurePosixPath(path).name.casefold()
	if lowered.startswith(('docs/','assets/','evidence/'))or name.endswith('.md')or name.startswith(('license','readme'))or name in{'authors','copying','notice'}:return'PUBLIC_DOCUMENTATION'
	if lowered.startswith(('contracts/','crates/','ffi/','include/','release/','schemas/','tools/haldir-ctl/')):return'PUBLIC_API_OR_SCHEMA'
	if lowered.startswith(('.github/','config/','configs/','deploy/','profiles/'))or name in{'.gitignore','.ncp-consumer','cargo.lock','cargo.toml','deny.toml','dockerfile','dockerfile.dockerignore','justfile','pins.toml','rust-toolchain.toml'}:return'BUILD_OR_DEPLOYMENT'
	return None
def surface_types(path:str,payload:bytes,classification:str)->list[str]:
	lowered=path.casefold();name=PurePosixPath(path).name.casefold();types:set[str]=set()
	if classification=='PUBLIC_DOCUMENTATION':types.add('DOCUMENTATION')
	if lowered.startswith('crates/')and lowered.endswith('.rs'):
		types.add('RUST_API_SOURCE')
		try:text=payload.decode('utf-8')
		except UnicodeDecodeError:text=''
		if any(PUBLIC_DECL_PATTERN.match(line)for line in text.splitlines()):types.add('RUST_PUBLIC_DECLARATION_SOURCE')
	if name=='cargo.toml':types.add('PACKAGE_MANIFEST')
	if lowered.startswith('.github/workflows/'):types.add('AUTOMATION_WORKFLOW')
	if lowered.startswith(('config/','configs/','deploy/','profiles/')):types.add('DEPLOYMENT_CONFIGURATION')
	if lowered.startswith(('contracts/','schemas/'))or name.endswith(('.json','.proto','.schema')):types.add('SCHEMA_OR_CONTRACT')
	if lowered.startswith('tools/haldir-ctl/')or'/src/bin/'in f"/{lowered}"or'/examples/'in f"/{lowered}":types.add('COMMAND_LINE_INTERFACE_SOURCE')
	try:text_lower=payload.decode('utf-8').casefold()
	except UnicodeDecodeError:text_lower=''
	if any(marker in text_lower for marker in('zenoh','route','keyexpr','interprocess','ipc')):types.add('IPC_OR_ROUTE_SOURCE')
	if lowered.startswith('release/'):types.add('RELEASE_RECORD')
	if not types:types.add('PUBLIC_FILE')
	return sorted(types)
def content_kind(path:str,payload:bytes)->str:
	binary_suffixes='.gz','.ico','.jpeg','.jpg','.pdf','.png','.wasm','.zip'
	if path.casefold().endswith(binary_suffixes)or b'\x00'in payload:return'BINARY'
	try:payload.decode('utf-8')
	except UnicodeDecodeError:return'BINARY'
	return'UTF8'
def recognized_file_name(path:str)->bool:
	name=PurePosixPath(path).name
	if name in KNOWN_EXTENSIONLESS_NAMES or name.casefold()in{'authors','copying','dockerfile','justfile','notice'}:return True
	lowered=name.casefold();return any(lowered.endswith(suffix)for suffix in KNOWN_FILE_SUFFIXES)
def inventory_classification(path:str)->tuple[str,str,str]:
	'Return the exact conservative classification for one frozen path.';lowered=path.casefold();name=PurePosixPath(path).name.casefold()
	if lowered.endswith(('.md','.rst','.txt'))or name.startswith(('readme','license'))or name in{'authors','copying','notice'}or lowered.startswith('assets/'):return'PUBLIC_DOCUMENTATION','SURFACE','HUMAN_OR_BRAND_DOCUMENTATION'
	if lowered.startswith(('contracts/','crates/','ffi/','include/','schemas/','formal/'))or lowered.startswith('tools/haldir-ctl/')or lowered.endswith(('.proto','.tla')):return'PUBLIC_API_OR_SCHEMA','SURFACE','CODE_SCHEMA_OR_FORMAL_INTERFACE'
	if lowered.startswith(('.github/','config/','configs/','deploy/','profiles/'))or name in{'.gitignore','.ncp-consumer','cargo.lock','cargo.toml','deny.toml','dockerfile','dockerfile.dockerignore','justfile','pins.toml','rust-toolchain.toml'}:return'BUILD_OR_DEPLOYMENT','SURFACE','BUILD_AUTOMATION_OR_DEPLOYMENT_INPUT'
	if lowered.startswith(('release/','audit/','evidence/')):return'EXCLUDED_INTERNAL_EVIDENCE_OR_RELEASE','EXCLUDED','RETAINED_ASSURANCE_OR_RELEASE_RECORD_NOT_RUNTIME_INTERFACE'
	if lowered.startswith('tools/')or'/tests/'in f"/{lowered}"or name.startswith('test_'):return'EXCLUDED_INTERNAL_TEST_OR_TOOL','EXCLUDED','INTERNAL_TEST_OR_ASSURANCE_TOOL_NOT_RUNTIME_INTERFACE'
	if lowered.startswith('assets/')or lowered.endswith(('.ico','.png','.svg')):return'EXCLUDED_NONINTERFACE_ASSET','EXCLUDED','NONINTERFACE_ASSET'
	raise VerifyError(f"UNCLASSIFIED_PATH:{path}")
def inventory_surface_types(path:str,payload:bytes,classification:str)->list[str]:
	lowered=path.casefold();name=PurePosixPath(path).name.casefold();result:set[str]=set()
	if classification=='PUBLIC_DOCUMENTATION':result.add('DOCUMENTATION')
	if lowered.startswith('crates/')and lowered.endswith('.rs'):
		result.add('RUST_API_SOURCE');text=payload.decode('utf-8')
		if re.search('(?m)^\\s*(?:#\\[[^\\n]+\\]\\s*)*pub\\s+',text)or'#[macro_export]'in text:result.add('RUST_PUBLIC_DECLARATION_SOURCE')
	if name=='cargo.toml':result.add('PACKAGE_MANIFEST')
	if lowered.startswith('.github/workflows/'):result.add('AUTOMATION_WORKFLOW')
	if lowered.startswith('deploy/'):result.add('DEPLOYMENT_CONFIGURATION')
	if lowered.startswith('contracts/')or name.endswith(('.proto','.schema.json')):result.add('SCHEMA_OR_CONTRACT')
	if lowered.startswith('formal/'):result.add('FORMAL_MODEL_OR_CONFIGURATION')
	if lowered.startswith('tools/haldir-ctl/')or'/src/bin/'in f"/{lowered}"or'/examples/'in f"/{lowered}"or name=='main.rs':result.add('COMMAND_LINE_INTERFACE_SOURCE')
	folded=payload.decode('utf-8',errors='ignore').casefold()
	if any(marker in folded for marker in('zenoh','keyexpr','interprocess','ipc','route')):result.add('IPC_OR_ROUTE_SOURCE')
	if lowered.startswith('release/'):result.add('RELEASE_RECORD')
	if not result:result.add('CLASSIFIED_FILE')
	return sorted(result)
def valid_archive_member_path(path:str)->bool:return valid_path(path)and'\\'not in path and not path.endswith('/')and len(path.encode('utf-8'))<=MAX_PATH_BYTES
def looks_like_archive(payload:bytes)->bool:return any(payload.startswith(prefix)for prefix in ARCHIVE_MAGIC_PREFIXES)or len(payload)>=262 and payload[257:262]==b'ustar'
def archive_member_record(container_path:str,member_path:str,payload:bytes,compressed_bytes:int,crc32:int|None)->dict[str,Any]:return{'container_path':container_path,'member_path':member_path,'bytes':len(payload),'compressed_bytes':compressed_bytes,'crc32':crc32,'sha256':sha256(payload),'content_kind':content_kind(member_path,payload),'claim_ids':claim_ids(payload)}
def inspect_archive(path:str,payload:bytes)->list[dict[str,Any]]:
	lowered=path.casefold()
	if lowered.endswith('.gz'):
		if len(payload)<18 or payload[:3]!=b'\x1f\x8b\x08'or payload[3]!=0:raise VerifyError('GZIP_HEADER')
		inflater=zlib.decompressobj(16+zlib.MAX_WBITS)
		try:expanded=inflater.decompress(payload,MAX_ARCHIVE_MEMBER_BYTES+1)
		except zlib.error as error:raise VerifyError('GZIP_INVALID')from error
		if not inflater.eof or inflater.unconsumed_tail or inflater.unused_data or len(expanded)>MAX_ARCHIVE_MEMBER_BYTES or len(expanded)>max(1,len(payload))*MAX_ARCHIVE_RATIO or looks_like_archive(expanded):raise VerifyError('GZIP_BOUNDARY')
		return[archive_member_record(path,PurePosixPath(path).name.removesuffix('.gz'),expanded,len(payload),None)]
	if not lowered.endswith('.zip'):raise VerifyError('ARCHIVE_SUFFIX')
	try:archive=zipfile.ZipFile(io.BytesIO(payload),'r')
	except(OSError,zipfile.BadZipFile)as error:raise VerifyError('ZIP_INVALID')from error
	records:list[dict[str,Any]]=[];names:set[str]=set();expanded_total=0;infos=archive.infolist()
	if not infos or len(infos)>MAX_ARCHIVE_MEMBERS:raise VerifyError('ZIP_MEMBER_COUNT')
	ordered_offsets=sorted(info.header_offset for info in infos);eocd_offset=payload.rfind(b'PK\x05\x06')
	if eocd_offset<0 or eocd_offset+22>len(payload):raise VerifyError('ZIP_EOCD')
	comment_length=int.from_bytes(payload[eocd_offset+20:eocd_offset+22],'little');central_size=int.from_bytes(payload[eocd_offset+12:eocd_offset+16],'little');central_offset=int.from_bytes(payload[eocd_offset+16:eocd_offset+20],'little')
	if len(set(ordered_offsets))!=len(ordered_offsets)or ordered_offsets[0]!=0 or int.from_bytes(payload[eocd_offset+4:eocd_offset+6],'little')!=0 or int.from_bytes(payload[eocd_offset+6:eocd_offset+8],'little')!=0 or int.from_bytes(payload[eocd_offset+8:eocd_offset+10],'little')!=len(infos)or int.from_bytes(payload[eocd_offset+10:eocd_offset+12],'little')!=len(infos)or central_offset!=archive.start_dir or central_offset+central_size!=eocd_offset or comment_length!=0 or archive.comment!=b''or eocd_offset+22+comment_length!=len(payload):raise VerifyError('ZIP_MEMBER_OVERLAP')
	offset_indexes={header_offset:index for(index,header_offset)in enumerate(ordered_offsets)}
	for info in infos:
		member_path=unicodedata.normalize('NFC',info.filename);mode_type=info.external_attr>>16&61440
		if member_path!=info.filename or not valid_archive_member_path(member_path)or member_path in names or info.flag_bits&~(2048|8)or info.compress_type not in{zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED}or info.comment!=b''or info.extra!=b''or member_path.casefold().endswith(NESTED_ARCHIVE_SUFFIXES)or mode_type not in{0,32768}or info.file_size<0 or info.file_size>MAX_ARCHIVE_MEMBER_BYTES or info.compress_size<0 or info.file_size>max(1,info.compress_size)*MAX_ARCHIVE_RATIO:raise VerifyError('ZIP_MEMBER_POLICY')
		offset_index=offset_indexes[info.header_offset];next_boundary=ordered_offsets[offset_index+1]if offset_index+1<len(ordered_offsets)else archive.start_dir;local_header=payload[info.header_offset:info.header_offset+30]
		if len(local_header)!=30 or local_header[:4]!=b'PK\x03\x04':raise VerifyError('ZIP_LOCAL_HEADER')
		name_length=int.from_bytes(local_header[26:28],'little');extra_length=int.from_bytes(local_header[28:30],'little');data_start=info.header_offset+30+name_length+extra_length;data_end=data_start+info.compress_size;local_name_start=info.header_offset+30;local_name_end=local_name_start+name_length;local_extra_end=local_name_end+extra_length;local_name=payload[local_name_start:local_name_end];local_extra=payload[local_name_end:local_extra_end]
		try:expected_name=info.orig_filename.encode('utf-8'if info.flag_bits&2048 else'cp437')
		except UnicodeEncodeError as error:raise VerifyError('ZIP_MEMBER_OVERLAP')from error
		year,month,day,hour,minute,second=info.date_time;expected_time=hour<<11|minute<<5|second//2;expected_date=year-1980<<9|month<<5|day;local_crc=int.from_bytes(local_header[14:18],'little');local_compressed=int.from_bytes(local_header[18:22],'little');local_expanded=int.from_bytes(local_header[22:26],'little')
		if info.flag_bits&8:descriptor=payload[data_end:data_end+16];envelope_end=data_end+16;descriptor_valid=len(descriptor)==16 and descriptor[:4]==b'PK\x07\x08'and int.from_bytes(descriptor[4:8],'little')==info.CRC and int.from_bytes(descriptor[8:12],'little')==info.compress_size and int.from_bytes(descriptor[12:16],'little')==info.file_size and local_crc==0 and local_compressed==0 and local_expanded==0
		else:envelope_end=data_end;descriptor_valid=local_crc==info.CRC and local_compressed==info.compress_size and local_expanded==info.file_size
		if int.from_bytes(local_header[4:6],'little')!=info.extract_version or int.from_bytes(local_header[6:8],'little')!=info.flag_bits or int.from_bytes(local_header[8:10],'little')!=info.compress_type or int.from_bytes(local_header[10:12],'little')!=expected_time or int.from_bytes(local_header[12:14],'little')!=expected_date or local_name!=expected_name or local_extra!=info.extra or data_start<info.header_offset+30 or data_end<data_start or not descriptor_valid or envelope_end!=next_boundary or next_boundary>archive.start_dir:raise VerifyError('ZIP_MEMBER_OVERLAP')
		names.add(member_path);expanded_total+=info.file_size
		if expanded_total>MAX_ARCHIVE_EXPANDED_BYTES:raise VerifyError('ZIP_EXPANDED_CAPACITY')
		compressed_payload=payload[data_start:data_end]
		if info.compress_type==zipfile.ZIP_STORED:member_payload=compressed_payload
		else:
			inflater=zlib.decompressobj(-zlib.MAX_WBITS)
			try:member_payload=inflater.decompress(compressed_payload,MAX_ARCHIVE_MEMBER_BYTES+1)
			except zlib.error as error:raise VerifyError('ZIP_MEMBER_INVALID')from error
			if inflater.unconsumed_tail or inflater.unused_data or not inflater.eof:raise VerifyError('ZIP_MEMBER_INVALID')
		if len(member_payload)!=info.file_size or zlib.crc32(member_payload)&4294967295!=info.CRC:raise VerifyError('ZIP_MEMBER_SIZE')
		if looks_like_archive(member_payload):raise VerifyError('ZIP_MEMBER_POLICY')
		records.append(archive_member_record(path,member_path,member_payload,info.compress_size,info.CRC))
	archive.close();return sorted(records,key=lambda item:item['member_path'].encode('utf-8'))
def expected_archive_inventory(entries:list[dict[str,Any]],blobs:dict[str,bytes])->tuple[list[dict[str,Any]],list[dict[str,Any]]]:
	containers:list[dict[str,Any]]=[];members:list[dict[str,Any]]=[]
	for entry in entries:
		path=entry['path']
		if not path.casefold().endswith(('.gz','.zip')):continue
		payload=blobs[path];container_members=inspect_archive(path,payload);kind='GZIP'if path.casefold().endswith('.gz')else'ZIP';containers.append({'path':path,'kind':kind,'bytes':len(payload),'sha256':sha256(payload),'members':len(container_members),'expanded_bytes':sum(item['bytes']for item in container_members)});members.extend(container_members)
	return containers,members
def claim_ids(payload:bytes)->list[str]:
	try:text=payload.decode('utf-8')
	except UnicodeDecodeError:return[]
	return sorted(set(CLAIM_PATTERN.findall(text)))
def yaml_value_without_comment(value:str,path:str,number:int)->str:
	stack:list[str]=[];quote:str|None=None;escaped=False;result:list[str]=[];pairs={']':'[','}':'{'};index=0
	while index<len(value):
		character=value[index]
		if quote=='"':
			result.append(character)
			if escaped:escaped=False
			elif character=='\\':escaped=True
			elif character==quote:quote=None
			index+=1;continue
		if quote=="'":
			result.append(character)
			if character=="'"and index+1<len(value)and value[index+1]=="'":result.append(value[index+1]);index+=2;continue
			if character=="'":quote=None
			index+=1;continue
		if character in{'"',"'"}:quote=character;result.append(character)
		elif character=='#'and(index==0 or value[index-1].isspace()):break
		elif character in'[{':stack.append(character);result.append(character)
		elif character in']}':
			if not stack or stack.pop()!=pairs[character]:raise VerifyError(f"YAML_DELIMITER:{path}:{number}")
			result.append(character)
		else:result.append(character)
		index+=1
	if quote is not None or escaped or stack:raise VerifyError(f"YAML_DELIMITER:{path}:{number}")
	return''.join(result).rstrip()
def validate_yaml_value(value:str,path:str,number:int)->str:
	value=yaml_value_without_comment(value,path,number)
	if not value:return'EMPTY'
	if re.fullmatch('[|>](?:[+-]|[1-9]|[+-][1-9]|[1-9][+-])?',value):return'BLOCK'
	if value[0]in'[{':
		normalized=re.sub('([,{]\\s*)([A-Za-z0-9_.${}/-]+)\\s*:','\\1"\\2":',value)
		try:load_json(normalized.encode('utf-8'),canonical=False)
		except VerifyError as error:raise VerifyError(f"YAML_FLOW_INVALID:{path}:{number}")from error
	elif value.startswith('"'):
		try:parsed=json.loads(value)
		except json.JSONDecodeError as error:raise VerifyError(f"YAML_QUOTED_SCALAR:{path}:{number}")from error
		if not isinstance(parsed,str):raise VerifyError(f"YAML_QUOTED_SCALAR:{path}:{number}")
		validate_unicode_scalars(parsed)
	elif value.startswith("'"):
		if len(value)<2 or not value.endswith("'")or re.search("(?<!')'(?!')",value[1:-1]):raise VerifyError(f"YAML_QUOTED_SCALAR:{path}:{number}")
	elif value.startswith(('*','&','!','---','...'))or re.search('(?:^|\\s)[&*!][^\\s]+',value)or re.search(':(?:\\s|$)',value):raise VerifyError(f"YAML_UNSUPPORTED_SCALAR:{path}:{number}")
	return'SCALAR'
YAML_KEY_PATTERN=re.compile('(?P<key>"(?:[^"\\\\]|\\\\.)*"|\'(?:[^\']|\'\')*\'|[A-Za-z0-9_.${}/-]+)\\s*:(?=\\s|$)')
def yaml_mapping_entry(text:str,path:str,number:int)->tuple[str,str]|None:
	match=YAML_KEY_PATTERN.match(text)
	if match is None:return None
	token=match.group('key')
	if token.startswith('"'):
		try:key=json.loads(token)
		except json.JSONDecodeError as error:raise VerifyError(f"YAML_KEY:{path}:{number}")from error
		validate_unicode_scalars(key)
	elif token.startswith("'"):key=token[1:-1].replace("''","'")
	else:key=token
	if not isinstance(key,str)or not key or key=='<<':raise VerifyError(f"YAML_KEY:{path}:{number}")
	return key,text[match.end():].lstrip()
def validate_yaml(payload:bytes,path:str)->None:
	try:lines=payload.decode('utf-8').splitlines()
	except UnicodeDecodeError as error:raise VerifyError(f"YAML_UTF8:{path}")from error
	scopes:list[tuple[int,str,set[str]]]=[];block_scalar_indent:int|None=None;pending_child_indent:int|None=None
	for(number,raw_line)in enumerate(lines,start=1):
		indent=len(raw_line)-len(raw_line.lstrip(' '))
		if block_scalar_indent is not None:
			if not raw_line.strip()or indent>block_scalar_indent:continue
			block_scalar_indent=None
		if not raw_line.strip()or raw_line.lstrip().startswith('#'):continue
		if'\t'in raw_line[:len(raw_line)-len(raw_line.lstrip())]:raise VerifyError(f"YAML_TAB_INDENT:{path}:{number}")
		if indent%2:raise VerifyError(f"YAML_INDENT:{path}:{number}")
		text=raw_line.strip()
		while scopes and scopes[-1][0]>indent:scopes.pop()
		if pending_child_indent is not None:
			if indent>pending_child_indent:
				if indent!=pending_child_indent+2:raise VerifyError(f"YAML_INDENT:{path}:{number}")
				kind='SEQUENCE'if text=='-'or text.startswith('- ')else'MAPPING';scopes.append((indent,kind,set()))
			pending_child_indent=None
		if not scopes:
			if indent!=0:raise VerifyError(f"YAML_INDENT:{path}:{number}")
			kind='SEQUENCE'if text=='-'or text.startswith('- ')else'MAPPING';scopes.append((0,kind,set()))
		if scopes[-1][0]!=indent:raise VerifyError(f"YAML_INDENT:{path}:{number}")
		kind=scopes[-1][1]
		if kind=='SEQUENCE':
			if text=='-':pending_child_indent=indent;continue
			if not text.startswith('- '):raise VerifyError(f"YAML_SEQUENCE:{path}:{number}")
			item=text[2:].lstrip();entry=yaml_mapping_entry(item,path,number)
			if entry is None:
				if validate_yaml_value(item,path,number)!='SCALAR':raise VerifyError(f"YAML_SEQUENCE_VALUE:{path}:{number}")
				continue
			key,value=entry;item_scope:set[str]={key};scopes.append((indent+2,'MAPPING',item_scope));status=validate_yaml_value(value,path,number)
			if status=='EMPTY':pending_child_indent=indent+2
			elif status=='BLOCK':block_scalar_indent=indent+2
			continue
		if text=='-'or text.startswith('- '):raise VerifyError(f"YAML_MAPPING:{path}:{number}")
		entry=yaml_mapping_entry(text,path,number)
		if entry is None:raise VerifyError(f"YAML_SYNTAX:{path}:{number}")
		key,value=entry;scope=scopes[-1][2]
		if key in scope:raise VerifyError(f"YAML_DUPLICATE_KEY:{path}:{number}:{key}")
		scope.add(key);status=validate_yaml_value(value,path,number)
		if status=='EMPTY':pending_child_indent=indent
		elif status=='BLOCK':block_scalar_indent=indent
def validate_structured_blob(path:str,payload:bytes)->None:
	lowered=path.casefold()
	if lowered.endswith('.toml'):
		try:tomllib.loads(payload.decode('utf-8'))
		except(UnicodeDecodeError,tomllib.TOMLDecodeError)as error:raise VerifyError(f"TOML_INVALID:{path}")from error
	elif lowered.endswith(('.yaml','.yml')):validate_yaml(payload,path)
	elif lowered.endswith(('.json','.json5')):load_json(payload,canonical=False)
def expected_public_records(repo:Path,implementation_commit:str,entries:list[dict[str,Any]]|None=None,blobs:dict[str,bytes]|None=None)->list[dict[str,Any]]:
	if entries is None or blobs is None:entries,blobs=tree_snapshot(repo,implementation_commit)
	result:list[dict[str,Any]]=[]
	for entry in entries:
		validate_structured_blob(entry['path'],blobs[entry['path']]);classification=classify_path(entry['path'])
		if classification is None:continue
		payload=blobs[entry['path']];result.append({**entry,'sha256':sha256(payload),'bytes':len(payload),'content_kind':content_kind(entry['path'],payload),'classification':classification,'surface_types':surface_types(entry['path'],payload,classification),'claim_ids':claim_ids(payload)})
	return result
def expected_declarations(repo:Path,implementation_commit:str,records:list[dict[str,Any]],blobs:dict[str,bytes]|None=None)->list[dict[str,Any]]:
	if blobs is None:_entries,blobs=tree_snapshot(repo,implementation_commit)
	declarations:list[dict[str,Any]]=[]
	for record in records:
		path=record['path'];payload=blobs[path]
		for surface_type in record['surface_types']:declarations.append({'kind':f"FILE_{surface_type}",'path':path,'name':path,'line':None,'signature_sha256':record['sha256']})
		if record['content_kind']!='UTF8':continue
		text=payload.decode('utf-8')
		if path.casefold().endswith('.rs'):
			for(number,line)in enumerate(text.splitlines(),start=1):
				if PUBLIC_DECL_PATTERN.match(line):declarations.append({'kind':'RUST_PUBLIC_DECLARATION','path':path,'name':f"line:{number}",'line':number,'signature_sha256':sha256(line.strip().encode('utf-8'))})
		lowered=path.casefold()
		if any(marker in text.casefold()for marker in('zenoh','route','keyexpr','interprocess','ipc')):
			for(number,line)in enumerate(text.splitlines(),start=1):
				lowered_line=line.casefold()
				if any(marker in lowered_line for marker in('zenoh','route','keyexpr','interprocess','ipc')):declarations.append({'kind':'IPC_OR_ROUTE_DECLARATION_LINE','path':path,'name':f"line:{number}",'line':number,'signature_sha256':sha256(line.encode('utf-8'))})
		if PurePosixPath(path).name=='Cargo.toml':
			try:manifest=tomllib.loads(text)
			except tomllib.TOMLDecodeError as error:raise VerifyError('CARGO_MANIFEST_INVALID')from error
			package=manifest.get('package')
			if isinstance(package,dict)and isinstance(package.get('name'),str):declarations.append({'kind':'CARGO_PACKAGE','path':path,'name':package['name'],'line':None,'signature_sha256':sha256(canonical_json(package))})
			features=manifest.get('features',{})
			if not isinstance(features,dict):raise VerifyError('CARGO_FEATURES_INVALID')
			for(name,members)in sorted(features.items()):
				if not isinstance(name,str)or not isinstance(members,list)or not all(isinstance(item,str)for item in members):raise VerifyError('CARGO_FEATURE_INVALID')
				declarations.append({'kind':'CARGO_FEATURE','path':path,'name':name,'line':None,'signature_sha256':sha256(canonical_json(members))})
			workspace=manifest.get('workspace')
			if isinstance(workspace,dict):
				members=workspace.get('members',[])
				if not isinstance(members,list)or not all(isinstance(item,str)for item in members):raise VerifyError('CARGO_WORKSPACE_INVALID')
				for member in sorted(members):declarations.append({'kind':'CARGO_WORKSPACE_MEMBER','path':path,'name':member,'line':None,'signature_sha256':sha256(member.encode('utf-8'))})
			for(table,kind)in(('bin','CARGO_BINARY_TARGET'),('example','CARGO_EXAMPLE_TARGET')):
				targets=manifest.get(table,[])
				if not isinstance(targets,list):raise VerifyError('CARGO_TARGET_INVALID')
				for target in targets:
					if not isinstance(target,dict)or not isinstance(target.get('name'),str):raise VerifyError('CARGO_TARGET_INVALID')
					declarations.append({'kind':kind,'path':path,'name':target['name'],'line':None,'signature_sha256':sha256(canonical_json(target))})
		if'/src/bin/'in f"/{lowered}"or'/examples/'in f"/{lowered}"or lowered.startswith('tools/haldir-ctl/'):declarations.append({'kind':'COMMAND_LINE_SOURCE','path':path,'name':path,'line':None,'signature_sha256':record['sha256']})
	declarations.sort(key=lambda item:(item['kind'],item['path'],-1 if item['line']is None else item['line'],item['name']))
	if len(declarations)>65536 or len({canonical_json(item)for item in declarations})!=len(declarations):raise VerifyError('DECLARATION_INVENTORY')
	return declarations
def parse_claim_rows(payload:bytes)->list[dict[str,str]]:
	try:lines=payload.decode('utf-8').splitlines()
	except UnicodeDecodeError as error:raise VerifyError('CLAIM_LEDGER_UTF8')from error
	result:list[dict[str,str]]=[];seen:set[str]=set()
	for line in lines:
		if not line.startswith('| CL-'):continue
		parts=[part.strip()for part in line[1:-1].split('|')];positions=[index for(index,part)in enumerate(parts)if part in CLAIM_STATUSES]
		if len(positions)!=1 or positions[0]<2 or positions[0]>=len(parts)-1:raise VerifyError('CLAIM_ROW_FORMAT')
		status_index=positions[0];claim_id=parts[0];statement='|'.join(parts[1:status_index]).strip();evidence='|'.join(parts[status_index+1:]).strip()
		if re.fullmatch('CL-[A-Z0-9]+(?:-[A-Z0-9]+)+',claim_id)is None or claim_id in seen or not statement or not evidence:raise VerifyError('CLAIM_ROW_INVALID')
		seen.add(claim_id);result.append({'id':claim_id,'statement':statement,'status':parts[status_index],'evidence':evidence,'statement_sha256':sha256(statement.encode('utf-8')),'evidence_sha256':sha256(evidence.encode('utf-8'))})
	if not result or len(result)>MAX_CLAIMS:raise VerifyError('CLAIM_COUNT')
	return sorted(result,key=lambda item:item['id'])
def expected_claim_tiers(repo:Path,implementation_commit:str,freeze_commit:str)->list[dict[str,Any]]:
	rows=parse_claim_rows(git_file(repo,implementation_commit,CLAIM_LEDGER_PATH));state=load_json(git_file(repo,freeze_commit,CLAIMS_STATE_PATH),canonical=False);active=set(state.get('active_claims',[]));non_claimed=set(state.get('non_claimed_claims',[]));removed=set(state.get('removed_claims',[]));ids={item['id']for item in rows}
	if ids!=active|non_claimed|removed or active&non_claimed or active&removed or non_claimed&removed:raise VerifyError('CLAIM_STATE_PARTITION')
	result:list[dict[str,Any]]=[]
	for row in rows:
		claim_id=row['id'];disposition='ACTIVE'
		if claim_id in non_claimed:disposition='NOT_CLAIMED'
		elif claim_id in removed:disposition='REMOVED'
		if claim_id==NARROWED_CLAIM:disposition='ACTIVE_NARROWED_PENDING_ACTIVATION'
		result.append({**row,'lifecycle_disposition':disposition,'evidence_tier':TIER_BY_STATUS[row['status']],'release_qualified':False})
	return result
def expected_language_hits(repo:Path,implementation_commit:str,records:list[dict[str,Any]],blobs:dict[str,bytes]|None=None)->list[dict[str,Any]]:
	if blobs is None:_entries,blobs=tree_snapshot(repo,implementation_commit)
	hits:list[dict[str,Any]]=[]
	for record in records:
		if record['content_kind']!='UTF8':continue
		text=blobs[record['path']].decode('utf-8')
		for(number,line)in enumerate(text.splitlines(),start=1):
			lowered=line.casefold();terms=[term for term in HIGH_RISK_TERMS if term in lowered]
			if not terms:continue
			hits.append({'path':record['path'],'line':number,'terms':terms,'claim_ids':sorted(set(CLAIM_PATTERN.findall(line))),'line_sha256':sha256(line.encode('utf-8'))})
			if len(hits)>MAX_LANGUAGE_HITS:raise VerifyError('CLAIM_LANGUAGE_CAPACITY')
	return hits
def expected_baseline_language_hits(entries:list[dict[str,Any]],blobs:dict[str,bytes])->tuple[list[str],list[dict[str,Any]],int]:
	paths=[item['path']for item in entries if item['path'].casefold().endswith(('.md','.rst','.txt'))];hits:list[dict[str,Any]]=[];matching_lines=0
	for path in paths:
		try:text=blobs[path].decode('utf-8')
		except UnicodeDecodeError as error:raise VerifyError('BASELINE_TEXT_UTF8')from error
		for(line_number,line)in enumerate(text.splitlines(),start=1):
			matches=list(BASELINE_CLAIM_REGEX.finditer(line))
			if matches:matching_lines+=1
			line_digest=sha256(line.encode('utf-8'));line_claims=sorted(set(CLAIM_PATTERN.findall(line)))
			for match in matches:hits.append({'scope':'HANDOFF_BASELINE_TRACKED_TEXT','path':path,'member':None,'endpoint':None,'line':line_number,'column':match.start()+1,'match':match.group(0),'normalized_term':re.sub('[-\\s]+',' ',match.group(0).casefold()),'claim_ids':line_claims,'line_sha256':line_digest})
	return paths,hits,matching_lines
def file_record(repo:Path,commit:str,path:str,entries:list[dict[str,Any]]|None=None,blobs:dict[str,bytes]|None=None)->dict[str,Any]:
	if entries is None or blobs is None:entries,blobs=tree_snapshot(repo,commit)
	entry=next((item for item in entries if item['path']==path),None)
	if entry is None:raise VerifyError('FILE_RECORD_MISSING')
	payload=blobs[path];return{'path':path,'sha256':sha256(payload),'bytes':len(payload),**{key:entry[key]for key in('git_mode','git_object_type','git_object_id')}}
def protocol_file_record(path:str,entries:list[dict[str,Any]],blobs:dict[str,bytes])->dict[str,Any]:
	entry=next((item for item in entries if item['path']==path),None)
	if entry is None or path not in blobs:raise VerifyError(f"PROTOCOL_FILE_MISSING:{path}")
	payload=blobs[path];record={'path':path,'sha256':sha256(payload),'bytes':len(payload),'git_mode':entry['git_mode'],'git_object_type':entry['git_object_type'],'git_object_id':entry['git_object_id']}
	try:text=payload.decode('utf-8')
	except UnicodeDecodeError:return record
	record['lines']=len(text.splitlines());return record
def exact_file_record(path:str,entries:list[dict[str,Any]],blobs:dict[str,bytes],*,include_selected_lines:bool=False)->dict[str,Any]:
	'Return the exact protocol identity used by C and D records.';record=protocol_file_record(path,entries,blobs)
	if include_selected_lines:
		if not(path.endswith(('.json','.py','.sh','.yml','.md'))or path=='justfile'):record.pop('lines',None)
	else:record.pop('lines',None)
	return record
def prospective_file_record(path:str,payload:bytes,*,include_selected_lines:bool=False)->dict[str,Any]:
	if not valid_path(path):raise VerifyError('PROSPECTIVE_FILE_PATH')
	record:dict[str,Any]={'path':path,'sha256':sha256(payload),'bytes':len(payload)}
	if include_selected_lines and(path.endswith(('.json','.py','.sh','.yml','.md'))or path=='justfile'):record['lines']=len(payload.splitlines())
	record.update({'git_mode':'100644','git_object_type':'blob','git_object_id':hashlib.sha1(f"blob {len(payload)}\x00".encode('ascii')+payload,usedforsecurity=False).hexdigest()});return record
def require_fields(value:Any,fields:set[str],label:str)->dict[str,Any]:
	if not isinstance(value,dict)or set(value)!=fields:raise VerifyError(f"FIELDS:{label}")
	return value
def parse_utc(value:Any)->datetime:
	if not isinstance(value,str)or re.fullmatch('\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z',value)is None:raise VerifyError('UTC_FORMAT')
	return datetime.fromisoformat(value.replace('Z','+00:00')).astimezone(timezone.utc)
def validate_github_metadata(value:Any,freeze_time:datetime,implementation_time:datetime)->None:
	record=require_fields(value,{'schema_version','task_id','release_target','author','persistent_identifier','captured_at_utc','captures','normalized','result'},'github_metadata')
	if record['schema_version']!='1.0.0'or record['task_id']!=TASK_ID or record['release_target']!=RELEASE_TARGET or record['author']!=AUTHOR or record['persistent_identifier']is not None or record['result']!='PASS':raise VerifyError('GITHUB_IDENTITY')
	captured=parse_utc(record['captured_at_utc'])
	if not freeze_time<=captured<=implementation_time:raise VerifyError('GITHUB_CHRONOLOGY')
	captures=record['captures'];expected_endpoints=['/repos/sepahead/haldir','/repos/sepahead/haldir/releases?per_page=100','/repos/sepahead/haldir/tags?per_page=100']
	if not isinstance(captures,list)or[item.get('endpoint')for item in captures if isinstance(item,dict)]!=expected_endpoints:raise VerifyError('GITHUB_ENDPOINTS')
	decoded:dict[str,Any]={}
	for item in captures:
		item=require_fields(item,{'endpoint','method','accept','body_base64','bytes','sha256'},'github_capture')
		try:payload=base64.b64decode(item['body_base64'],validate=True)
		except(ValueError,TypeError)as error:raise VerifyError('GITHUB_BASE64')from error
		if item['method']!='GET'or item['accept']!='application/vnd.github+json'or item['bytes']!=len(payload)or item['sha256']!=sha256(payload)or len(payload)>262144:raise VerifyError('GITHUB_CAPTURE_BINDING')
		decoded[item['endpoint']]=load_json(payload,canonical=False,maximum=262144)
	repository=decoded[expected_endpoints[0]];releases=decoded[expected_endpoints[1]];tags=decoded[expected_endpoints[2]]
	if not isinstance(repository,dict)or not isinstance(releases,list)or not isinstance(tags,list):raise VerifyError('GITHUB_RESPONSE_SHAPE')
	normalized={'node_id':repository.get('node_id'),'owner':(repository.get('owner')or{}).get('login')if isinstance(repository.get('owner'),dict)else None,'name':repository.get('name'),'full_name':repository.get('full_name'),'default_branch':repository.get('default_branch'),'private':repository.get('private'),'visibility':repository.get('visibility'),'archived':repository.get('archived'),'disabled':repository.get('disabled'),'description':repository.get('description'),'homepage':repository.get('homepage'),'topics':sorted(repository.get('topics',[]))if isinstance(repository.get('topics'),list)else None,'license_spdx':(repository.get('license')or{}).get('spdx_id')if isinstance(repository.get('license'),dict)else None,'open_issues_count':repository.get('open_issues_count'),'tag_count_observed':len(tags),'release_count_observed':len(releases)}
	if record['normalized']!=normalized or normalized['owner']!='sepahead'or normalized['name']!='haldir'or normalized['full_name']!='sepahead/haldir'or normalized['default_branch']!='main'or normalized['private']is not False or normalized['archived']is not False or normalized['disabled']is not False or normalized['tag_count_observed']!=0 or normalized['release_count_observed']!=0:raise VerifyError('GITHUB_NORMALIZED')
def validate_ledger_composition(value:Any,repo:Path,implementation_commit:str,entries:list[dict[str,Any]],blobs:dict[str,bytes])->None:
	record=require_fields(value,{'schema_version','task_id','release_target','author','persistent_identifier','prior_lifecycle','artifacts','review_boundary','result'},'ledger_composition')
	if record['schema_version']!='1.0.0'or record['task_id']!=TASK_ID or record['release_target']!=RELEASE_TARGET or record['author']!=AUTHOR or record['persistent_identifier']is not None or record['result']!='PASS':raise VerifyError('COMPOSITION_IDENTITY')
	expected_lifecycle={'freeze_commit':PRIOR_FREEZE,'implementation_commit':PRIOR_IMPLEMENTATION,'qualification_commit':PRIOR_QUALIFICATION,'activation_commit':PRIOR_ACTIVATION}
	if record['prior_lifecycle']!=expected_lifecycle:raise VerifyError('COMPOSITION_LIFECYCLE')
	paths=['audit/generated/FILE_REVIEW_LEDGER.csv','audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json','release/0.9.0/current-head/tasks/ch-t002/e0002/evidence/file-review-packet-manifest.json','release/0.9.0/current-head/tasks/ch-t002/e0002/qualification.json','release/0.9.0/current-head/tasks/ch-t002/e0002/activation.json']
	if record['artifacts']!=[file_record(repo,implementation_commit,path,entries,blobs)for path in paths]:raise VerifyError('COMPOSITION_ARTIFACTS')
	if record['review_boundary']!={'automated_review_only':True,'named_human_review_performed':False,'external_human_review_performed':False,'new_task_files_reviewed_in_ch_t003_qualification':True,'retroactive_ch_t002_subject_claim':False}:raise VerifyError('COMPOSITION_REVIEW_BOUNDARY')
def commit_time(repo:Path,commit:str)->datetime:
	raw=git_text(repo,'show','-s','--format=%cI',commit)
	try:return datetime.fromisoformat(raw).astimezone(timezone.utc)
	except ValueError as error:raise VerifyError('COMMIT_TIME')from error
COMMON_PRODUCT_FIELDS={'schema_version','schema_id','task_id','release_target','author','persistent_identifier','result'}
def require_product_identity(value:Any,schema_id:str,product_fields:set[str],label:str)->dict[str,Any]:
	record=require_fields(value,COMMON_PRODUCT_FIELDS|product_fields,label)
	if record['schema_version']!='1.0.0'or record['schema_id']!=schema_id or record['task_id']!=TASK_ID or record['release_target']!=RELEASE_TARGET or record['author']!=AUTHOR or record['persistent_identifier']is not None or record['result']!='PASS':raise VerifyError(f"IDENTITY:{label}")
	return record
def required_subset(value:Any,required:set[str],label:str)->dict[str,Any]:
	if not isinstance(value,dict)or not required.issubset(value):raise VerifyError(f"SUBSET:{label}")
	return value
def digest_matches(value:Any,expected_value:Any,label:str)->None:
	if value!=sha256(canonical_json(expected_value)):raise VerifyError(f"DIGEST:{label}")
def validate_inventory_file_records(records:Any,entries:list[dict[str,Any]],blobs:dict[str,bytes])->None:
	if not isinstance(records,list)or len(records)!=len(entries)or len(entries)!=426:raise VerifyError('PUBLIC_FILE_COUNT')
	paths=[item.get('path')for item in records if isinstance(item,dict)];expected_paths=[item['path']for item in entries]
	if paths!=expected_paths or paths!=sorted(paths,key=lambda item:item.encode('utf-8'))or len(set(paths))!=len(paths):raise VerifyError('PUBLIC_FILE_PARTITION')
	for(record,entry)in zip(records,entries,strict=True):
		record=require_fields(record,{'path','git_mode','git_object_type','git_object_id','bytes','sha256','lines','content_kind','classification','disposition','classification_reason','surface_types','claim_ids'},'public_file');path=entry['path'];payload=blobs[path];expected_classification=inventory_classification(path);expected_lines=len(payload.decode('utf-8').splitlines())if content_kind(path,payload)=='UTF8'else None
		if not recognized_file_name(path)or record['git_mode']!=entry['git_mode']or record['git_object_type']!='blob'or record['git_object_id']!=entry['git_object_id']or record['bytes']!=len(payload)or record['sha256']!=sha256(payload)or record['lines']!=expected_lines or record['content_kind']!=content_kind(path,payload)or record['claim_ids']!=claim_ids(payload)or(record['classification'],record['disposition'],record['classification_reason'])!=expected_classification:raise VerifyError('PUBLIC_FILE_IDENTITY')
		classifications=record['surface_types']
		if not isinstance(classifications,list)or classifications!=inventory_surface_types(path,payload,record['classification']):raise VerifyError('PUBLIC_FILE_CLASSIFICATION')
def validate_candidate_plan(value:Any,implementation_entries:list[dict[str,Any]],implementation_blobs:dict[str,bytes])->None:
	section=require_fields(value,{'records','paths_sha256','records_sha256','expected_implementation_regular_blobs','cycle_boundary'},'candidate_implementation');records=section['records']
	if not isinstance(records,list):raise VerifyError('CANDIDATE_RECORDS')
	paths=[item.get('path')for item in records if isinstance(item,dict)]
	if paths!=list(IMPLEMENTATION_PLAN):raise VerifyError('CANDIDATE_PATHS')
	cyclic_outputs={CLAIM_TIER_PATH,REVIEW_OVERLAY_PATH,GITHUB_METADATA_PATH,LEDGER_COMPOSITION_PATH,PUBLIC_INVENTORY_PATH,CLAIM_LANGUAGE_PATH};implementation_map={item['path']:item for item in implementation_entries}
	for record in records:
		record=require_fields(record,{'path','change','binding_kind','sha256','bytes'},'candidate_record');path=record['path']
		if record['change']!=IMPLEMENTATION_PLAN[path]:raise VerifyError('CANDIDATE_STATUS')
		if path in cyclic_outputs:
			if record['binding_kind']!='NO_INNER_DIGEST'or record['sha256']is not None or record['bytes']is not None:raise VerifyError('CANDIDATE_CYCLE_BINDING')
			continue
		expected=implementation_map.get(path)
		if expected is None:raise VerifyError('CANDIDATE_IDENTITY_MISSING')
		payload=implementation_blobs[path]
		if record['binding_kind']!='EXACT_CANDIDATE_BYTES'or record['bytes']!=len(payload)or record['sha256']!=sha256(payload):raise VerifyError('CANDIDATE_IDENTITY')
	if section['expected_implementation_regular_blobs']!=434 or not isinstance(section['cycle_boundary'],str)or not section['cycle_boundary']or section['paths_sha256']!=sha256(canonical_json(list(IMPLEMENTATION_PLAN)))or section['records_sha256']!=sha256(canonical_json(records)):raise VerifyError('CANDIDATE_SUMMARY')
def validate_archive_products(value:Any,entries:list[dict[str,Any]],blobs:dict[str,bytes])->None:
	containers=value
	if not isinstance(containers,list):raise VerifyError('ARCHIVE_CONTAINERS')
	expected_containers,expected_members=expected_archive_inventory(entries,blobs)
	if len(containers)!=34 or len(expected_containers)!=34 or len(expected_members)!=148 or sum(item['bytes']for item in expected_members)!=8491897:raise VerifyError('ARCHIVE_CONTAINER_COUNT')
	expected_member_map={(item['container_path'],item['member_path']):item for item in expected_members};observed_member_keys:set[tuple[str,str]]=set()
	for(container,expected)in zip(containers,expected_containers,strict=True):
		container=require_fields(container,{'path','archive_type','source_sha256','source_bytes','members','member_count','expanded_bytes','members_sha256'},'archive_container')
		if container['path']!=expected['path']or container['archive_type']!=expected['kind']or container['source_sha256']!=expected['sha256']or container['source_bytes']!=expected['bytes']or container['member_count']!=expected['members']or container['expanded_bytes']!=expected['expanded_bytes']or not isinstance(container['members'],list)or len(container['members'])!=expected['members']:raise VerifyError('ARCHIVE_CONTAINER_IDENTITY')
		digest_matches(container['members_sha256'],container['members'],'archive_members');expected_sequence=[item['member_path']for item in expected_members if item['container_path']==container['path']]
		if[item.get('name')for item in container['members']]!=expected_sequence:raise VerifyError('ARCHIVE_MEMBER_ORDER')
		for member in container['members']:
			member=require_fields(member,{'name','bytes','compressed_bytes','crc32','sha256','content_kind','claim_ids'},'archive_member');key=container['path'],member['name'];expected_member=expected_member_map.get(key)
			if expected_member is None or key in observed_member_keys or member['bytes']!=expected_member['bytes']or member['compressed_bytes']!=expected_member['compressed_bytes']or member['crc32']!=expected_member['crc32']or member['sha256']!=expected_member['sha256']or member['content_kind']!=expected_member['content_kind']or member['claim_ids']!=expected_member['claim_ids']:raise VerifyError('ARCHIVE_MEMBER_IDENTITY')
			observed_member_keys.add(key)
	if observed_member_keys!=set(expected_member_map):raise VerifyError('ARCHIVE_MEMBER_PARTITION')
EXPECTED_LIBRARY_PACKAGES={'haldir-admission','haldir-contracts','haldir-core','haldir-crypto','haldir-deployment','haldir-durable','haldir-evidence','haldir-gate','haldir-ncp08','haldir-policy-native','haldir-range','haldir-reference-plant','haldir-state','haldir-testkit','haldir-transport-zenoh'}
EXPECTED_RUST_TARGETS={'aarch64-apple-darwin','x86_64-unknown-linux-gnu'}
EXPECTED_EXPORTED_MACROS={'__hc_build','__hc_count','__hc_encode','__hc_field_ty','__hc_raw_ty','canonical_struct','tagged_enum'}
EXPECTED_BUILDER_FAMILIES={'application','challenge','decision','final_command','intent','state'}
EXPECTED_LIVE_FAMILIES={'final_command','intent'}
EXPECTED_ABSENT_PROTOCOLS={'DDS','FFI','GRPC','HTTP','MAVROS','ROS','SHARED_MEMORY'}
EXPECTED_CANONICAL_MESSAGES={'AdmissionRecordV1':'haldir.admission_record','AuthorityRevocationV1':'haldir.authority_revocation','ControllerBundleManifestV1':'haldir.controller_bundle','DecisionReceiptV1':'haldir.decision_receipt','DeploymentPackageV1':'haldir.deployment_package','GateChallengeV1':'haldir.gate_challenge','GateStatusV1':'haldir.gate_status','HaldirIntentV1':'haldir.intent','MissionLeaseV1':'haldir.mission_lease','NcpCompatibilityArtifactV1':'haldir.ncp_compatibility','PublicationStageEventV1':'haldir.publication_stage'}
def bounded_gzip_decode(value:str,expected_bytes:int)->bytes:
	if not isinstance(value,str):raise VerifyError('GZIP_BASE64_TYPE')
	try:compressed=base64.b64decode(value,validate=True)
	except(ValueError,TypeError)as error:raise VerifyError('GZIP_BASE64')from error
	if len(compressed)>MAX_JSON_BYTES:raise VerifyError('GZIP_COMPRESSED_CAPACITY')
	inflater=zlib.decompressobj(16+zlib.MAX_WBITS)
	try:payload=inflater.decompress(compressed,MAX_ARCHIVE_MEMBER_BYTES+1)
	except zlib.error as error:raise VerifyError('GZIP_BUNDLE_INVALID')from error
	if not inflater.eof or inflater.unused_data or inflater.unconsumed_tail or len(payload)!=expected_bytes or len(payload)>MAX_ARCHIVE_MEMBER_BYTES:raise VerifyError('GZIP_BUNDLE_BOUNDARY')
	return payload
def validate_rust_api(value:Any,package_features:dict[str,set[str]]|None=None)->None:
	section=require_fields(value,{'policy','documents','observations','macro_invariant','counts','documents_sha256','observations_sha256'},'rust_api');documents=section['documents'];observations=section['observations']
	if not isinstance(documents,list)or not isinstance(observations,list)or len(observations)!=100:raise VerifyError('RUST_API_CARDINALITY')
	document_payloads:dict[str,bytes]={};document_lines:dict[str,int]={}
	for document in documents:
		document=require_fields(document,{'sha256','bytes','lines','encoding','encoded_bytes','encoded_sha256','listing_gzip_base64'},'rust_api_document')
		if document['encoding']!='gzip+base64'or type(document['bytes'])is not int or not 1<=document['bytes']<=MAX_ARCHIVE_MEMBER_BYTES or type(document['lines'])is not int or document['lines']<1 or document['sha256']in document_payloads:raise VerifyError('RUST_API_DOCUMENT_IDENTITY')
		try:compressed=base64.b64decode(document['listing_gzip_base64'],validate=True)
		except(ValueError,TypeError)as error:raise VerifyError('RUST_API_DOCUMENT_BASE64')from error
		payload=bounded_gzip_decode(document['listing_gzip_base64'],document['bytes'])
		if document['encoded_bytes']!=len(compressed)or document['encoded_sha256']!=sha256(compressed)or document['sha256']!=sha256(payload)or document['lines']!=len(payload.splitlines())or b'\x00'in payload or b'\r'in payload:raise VerifyError('RUST_API_DOCUMENT_BINDING')
		try:payload.decode('utf-8')
		except UnicodeDecodeError as error:raise VerifyError('RUST_API_DOCUMENT_UTF8')from error
		document_payloads[document['sha256']]=payload;document_lines[document['sha256']]=document['lines']
	digest_matches(section['documents_sha256'],documents,'rust_api_documents');seen_cells:set[tuple[str,str,str]]=set();observed_packages:set[str]=set();observed_targets:set[str]=set()
	for observation in observations:
		observation=require_fields(observation,{'package','target','configuration','feature_arguments','rustdoc_json_format','api_document_sha256','api_lines'},'rust_api_observation');cell=observation['package'],observation['target'],observation['configuration'];configuration=observation['configuration'];expected_arguments:list[str]|None=None
		if configuration=='DEFAULT':expected_arguments=[]
		elif configuration=='NO_DEFAULT':expected_arguments=['--no-default-features']
		elif configuration=='ALL_FEATURES':expected_arguments=['--all-features']
		elif isinstance(configuration,str)and configuration.startswith('FEATURE:'):
			feature=configuration.removeprefix('FEATURE:')
			if package_features is not None and feature in package_features.get(observation['package'],set()):expected_arguments=['--no-default-features','--features',feature]
		if cell in seen_cells or observation['package']not in EXPECTED_LIBRARY_PACKAGES or observation['target']not in EXPECTED_RUST_TARGETS or expected_arguments is None or observation['feature_arguments']!=expected_arguments or observation['rustdoc_json_format']!=57 or observation['api_document_sha256']not in document_payloads or observation['api_lines']!=document_lines[observation['api_document_sha256']]:raise VerifyError('RUST_API_OBSERVATION')
		seen_cells.add(cell);observed_packages.add(observation['package']);observed_targets.add(observation['target'])
	if observed_packages!=EXPECTED_LIBRARY_PACKAGES or observed_targets!=EXPECTED_RUST_TARGETS:raise VerifyError('RUST_API_MATRIX')
	if package_features is not None:
		expected_cells={(package,target,configuration)for package in EXPECTED_LIBRARY_PACKAGES for target in EXPECTED_RUST_TARGETS for configuration in('DEFAULT','NO_DEFAULT',*(f"FEATURE:{feature}"for feature in sorted(package_features.get(package,set()))),'ALL_FEATURES')}
		if seen_cells!=expected_cells or len(expected_cells)!=100:raise VerifyError('RUST_API_EXACT_MATRIX')
	digest_matches(section['observations_sha256'],observations,'rust_api_observations');policy_text=canonical_json(section['policy']).decode('utf-8')
	for token in('0.52.0','1.96.0','acdc7b1733d52476fc2ce456a2a0292b82c367566fe0d2ab15c12b99974c8d24','RUSTC_BOOTSTRAP','CARGO_NET_OFFLINE','--document-hidden-items','--locked','--offline'):
		if token not in policy_text:raise VerifyError('RUST_API_POLICY')
	all_api_text=b'\n'.join(document_payloads.values()).decode('utf-8');observed_macros={match.group(1)for match in re.finditer('^pub macro haldir_contracts::([A-Za-z0-9_]+)!$',all_api_text,flags=re.MULTILINE)}
	if observed_macros!=EXPECTED_EXPORTED_MACROS or'HARD_MAX_INTENT_BYTES'not in all_api_text or'HARD_MAX_INTENT_QUEUE'in all_api_text or'HARD_MAX_ZENOH_MESSAGE_BYTES'in all_api_text or'HARD_MAX_ZENOH_RX_BUFFER_BYTES'in all_api_text:raise VerifyError('RUST_API_REACHABILITY')
	macro=require_fields(section['macro_invariant'],{'package','expected','observed','result'},'macro_invariant')
	if macro['package']!='haldir-contracts'or macro['expected']!=sorted(EXPECTED_EXPORTED_MACROS)or macro['observed']!=sorted(EXPECTED_EXPORTED_MACROS)or macro['result']!='PASS':raise VerifyError('RUST_API_MACROS')
def load_json_strict_noncanonical(payload:bytes)->Any:return load_json(payload,canonical=False)
def validate_ipc(value:Any,freeze_blobs:dict[str,bytes])->None:
	section=require_fields(value,{'profile','builder_families','live_bound_families','profile_routes_without_live_binding','absent_protocols','documentation_mentions_observed','boundary','counts'},'ipc');profile_payload=freeze_blobs.get('deploy/secure-reference-v1/profile.json')
	if profile_payload is None:raise VerifyError('IPC_PROFILE_MISSING')
	profile=load_json_strict_noncanonical(profile_payload)
	if not isinstance(profile,dict)or not isinstance(profile.get('routes'),dict):raise VerifyError('IPC_PROFILE_SHAPE')
	expected_routes=profile['routes'];observed_profile=require_fields(section['profile'],{'path','sha256','profile_id','realm','session_id','routes','principals'},'ipc_profile')
	if observed_profile['path']!='deploy/secure-reference-v1/profile.json'or observed_profile['sha256']!=sha256(profile_payload)or observed_profile['profile_id']!=profile.get('profile_id')or observed_profile['realm']!=profile.get('realm')or observed_profile['session_id']!=profile.get('session_id'):raise VerifyError('IPC_PROFILE_IDENTITY')
	routes=observed_profile['routes']
	if not isinstance(routes,list)or len(routes)!=17:raise VerifyError('IPC_ROUTE_COUNT')
	route_map:dict[str,str]={}
	for route in routes:
		route=require_fields(route,{'id','key_expression','status'},'ipc_route')
		if route['id']in route_map or not isinstance(route['key_expression'],str)or any(token in route['key_expression']for token in('*','$','?'))or route['status']!='PROFILE_DECLARED':raise VerifyError('IPC_ROUTE_POLICY')
		route_map[route['id']]=route['key_expression']
	if route_map!=expected_routes:raise VerifyError('IPC_ROUTE_IDENTITY')
	expected_principals=profile.get('principals');observed_principals=observed_profile['principals']
	if not isinstance(expected_principals,dict)or len(expected_principals)!=8 or observed_principals!=[{'id':identifier,**expected_principals[identifier]}for identifier in sorted(expected_principals)]:raise VerifyError('IPC_PRINCIPALS')
	builders=section['builder_families']
	if not isinstance(builders,list):raise VerifyError('IPC_BUILDERS')
	builder_names:set[str]=set();fixture_route_ids:set[str]=set()
	for builder in builders:
		builder=require_fields(builder,{'family','method','fixture_route_ids','implementation_status'},'ipc_builder')
		if builder['family']in builder_names or not isinstance(builder['method'],str)or not builder['method']or not isinstance(builder['fixture_route_ids'],list)or not all(isinstance(item,str)and item in expected_routes for item in builder['fixture_route_ids'])or not isinstance(builder['implementation_status'],str)or not builder['implementation_status']:raise VerifyError('IPC_BUILDER_POLICY')
		builder_names.add(builder['family']);fixture_route_ids.update(builder['fixture_route_ids'])
	if builder_names!=EXPECTED_BUILDER_FAMILIES or len(fixture_route_ids)!=7:raise VerifyError('IPC_BUILDER_PARTITION')
	expected_builders={'application':('HaldirKeys::application',['application_evidence']),'challenge':('HaldirKeys::challenge',['gate_challenge']),'decision':('HaldirKeys::decision',['decision_evidence']),'final_command':('HaldirKeys::final_command',['final_command']),'intent':('HaldirKeys::intent',['controller_a_intent','controller_b_intent']),'state':('HaldirKeys::state',['state_pose'])}
	if{item['family']:(item['method'],item['fixture_route_ids'],item['implementation_status'])for item in builders}!={family:(method,fixture_ids,'BUILDER_AVAILABLE')for(family,(method,fixture_ids))in expected_builders.items()}:raise VerifyError('IPC_BUILDERS_EXACT')
	live=section['live_bound_families']
	if not isinstance(live,list):raise VerifyError('IPC_LIVE')
	live_names:set[str]=set()
	for binding in live:
		binding=require_fields(binding,{'family','role','source','type','status'},'ipc_live_binding')
		if binding['family']in live_names or not all(isinstance(binding[field],str)and binding[field]for field in('role','source','type'))or binding['status']!='LIVE_BOUND':raise VerifyError('IPC_LIVE_POLICY')
		live_names.add(binding['family'])
	if live_names!=EXPECTED_LIVE_FAMILIES:raise VerifyError('IPC_LIVE_PARTITION')
	if{item['family']:(item['role'],item['source'],item['type'],item['status'])for item in live}!={'intent':('SUBSCRIBER','crates/haldir-transport-zenoh/src/live.rs','IntentIngress','LIVE_BOUND'),'final_command':('PUBLISHER','crates/haldir-transport-zenoh/src/live.rs','FinalCommandPublisher','LIVE_BOUND')}:raise VerifyError('IPC_LIVE_EXACT')
	absent=section['absent_protocols']
	if not isinstance(absent,list)or set(absent)!=EXPECTED_ABSENT_PROTOCOLS or len(absent)!=len(EXPECTED_ABSENT_PROTOCOLS):raise VerifyError('IPC_ABSENT_PROTOCOLS')
	ipc_text=canonical_json(section).decode('utf-8')
	for token in('Remote','live-zenoh','256','64','PROFILE_DECLARED','BUILDER_AVAILABLE','LIVE_BOUND'):
		if token not in ipc_text:raise VerifyError('IPC_EVIDENCE_LAYERS')
	expected_not_live=sorted(set(expected_routes)-{'controller_a_intent','controller_b_intent','final_command'});expected_mentions={name:any(name in payload.decode('utf-8',errors='ignore').casefold()for payload in freeze_blobs.values())for name in('engram','galadriel','prisoma')}
	if section['profile_routes_without_live_binding']!=expected_not_live or section['documentation_mentions_observed']!=expected_mentions or section['boundary']!={'profile_declaration_is_not_live_binding':True,'builder_availability_is_not_live_binding':True,'live_transport_feature_default':False,'live_transport_feature':'live-zenoh','remote_identity_boundary':'A received sample has a Remote route and payload identity, but it does not expose the peer certificate identity.','maximum_complete_route_bytes':256,'maximum_identifier_segment_bytes':64}or section['counts']!={'profile_routes':17,'principals':8,'builder_families':6,'builder_fixture_route_ids':7,'live_bound_families':2,'profile_routes_without_live_binding':len(expected_not_live)}:raise VerifyError('IPC_SUMMARY')
def validate_schemas(value:Any,freeze_blobs:dict[str,bytes]|None=None)->None:
	section=require_fields(value,{'canonical_messages','nested_canonical_values','tagged_enums','handwritten_contract_traits','json_records','boundary','counts'},'schemas');messages=section['canonical_messages']
	if not isinstance(messages,list)or len(messages)!=11:raise VerifyError('SCHEMA_MESSAGE_COUNT')
	observed:dict[str,str]={};observed_kinds:set[str]=set()
	for message in messages:
		message=require_fields(message,{'name','kind','path','line','key_tags'},'canonical_message');tags=message['key_tags']
		if message['name']in observed or message['kind']in observed_kinds or not valid_path(message['path'])or type(message['line'])is not int or message['line']<1 or not isinstance(tags,list)or not tags:raise VerifyError('SCHEMA_MESSAGE_IDENTITY')
		keys:list[int]=[];fields:set[str]=set()
		for tag in tags:
			tag=require_fields(tag,{'presence','key','field'},'canonical_key_tag')
			if tag['presence']not in{'req','opt'}or type(tag['key'])is not int or tag['key']<2 or tag['key']in keys or not isinstance(tag['field'],str)or not tag['field']or tag['field']in fields:raise VerifyError('SCHEMA_KEY_TAG')
			keys.append(tag['key']);fields.add(tag['field'])
		if keys!=sorted(keys):raise VerifyError('SCHEMA_KEY_ORDER')
		observed[message['name']]=message['kind'];observed_kinds.add(message['kind'])
		if freeze_blobs is not None:
			payload=freeze_blobs.get(message['path'])
			if payload is None:raise VerifyError('SCHEMA_MESSAGE_SOURCE')
			text=payload.decode('utf-8');source_pattern=re.compile(rf"pub\s+struct\s+{re.escape(message["name"])}\s+kind\s+\"{re.escape(message["kind"])}\"\s*\{{");source_match=source_pattern.search(text)
			if source_match is None or text.count('\n',0,source_match.start())+1!=message['line']:raise VerifyError('SCHEMA_MESSAGE_SOURCE')
			closing=text.find('\n}',source_match.end())
			if closing<0:raise VerifyError('SCHEMA_MESSAGE_SOURCE')
			source_tags=[{'presence':match.group(1),'key':int(match.group(2)),'field':match.group(3)}for match in re.finditer('(?m)^\\s*(req|opt)\\s+(\\d+)\\s+([A-Za-z0-9_]+)\\s*:',text[source_match.end():closing])]
			if source_tags!=tags:raise VerifyError('SCHEMA_MESSAGE_TAG_SOURCE')
	if observed!=EXPECTED_CANONICAL_MESSAGES:raise VerifyError('SCHEMA_MESSAGE_PARTITION')
	json_records=section['json_records']
	if not isinstance(json_records,list)or not json_records:raise VerifyError('SCHEMA_JSON_RECORDS')
	allowed_kinds={'DEFINITION','LIVE_EVIDENCE_INSTANCE','ORDINARY_JSON_RECORD','RETAINED_INSTANCE','VERIFIED_VECTOR'};paths:set[str]=set();expected_json_records:list[dict[str,Any]]=[]
	if freeze_blobs is not None:
		type_names={dict:'OBJECT',list:'ARRAY',str:'STRING',bool:'BOOLEAN',type(None):'NULL',int:'NUMBER',float:'NUMBER'}
		for(path,payload)in sorted(freeze_blobs.items()):
			if not path.casefold().endswith('.json'):continue
			parsed=load_json(payload,canonical=False)
			if path.casefold().endswith('.schema.json')or isinstance(parsed,dict)and'$schema'in parsed and('properties'in parsed or'$defs'in parsed):kind='DEFINITION'
			elif path.startswith(('evidence/11-','evidence/12-')):kind='LIVE_EVIDENCE_INSTANCE'
			elif'/tests/data/'in f"/{path}"or path.startswith('contracts/vectors/'):kind='VERIFIED_VECTOR'
			elif path.startswith(('release/','audit/','evidence/')):kind='RETAINED_INSTANCE'
			else:kind='ORDINARY_JSON_RECORD'
			expected_json_records.append({'path':path,'sha256':sha256(payload),'kind':kind,'top_level_type':type_names[type(parsed)],'schema_version':parsed.get('schema_version')if isinstance(parsed,dict)else None})
	for record in json_records:
		record=require_fields(record,{'path','sha256','kind','top_level_type','schema_version'},'schema_json_record')
		if record['path']in paths or not valid_path(record['path'])or re.fullmatch('[0-9a-f]{64}',record['sha256'])is None or record['kind']not in allowed_kinds or record['top_level_type']not in{'ARRAY','BOOLEAN','NULL','NUMBER','OBJECT','STRING'}or record['kind']=='DEFINITION'and not(record['path'].startswith(('contracts/','schemas/'))or record['path'].endswith('.schema.json')):raise VerifyError('SCHEMA_JSON_CLASSIFICATION')
		paths.add(record['path'])
	if freeze_blobs is not None and json_records!=expected_json_records:raise VerifyError('SCHEMA_JSON_SOURCE_PARTITION')
	for(collection_name,name_key)in(('nested_canonical_values','name'),('tagged_enums','name')):
		collection=section[collection_name]
		if not isinstance(collection,list):raise VerifyError('SCHEMA_SOURCE_COLLECTION')
		seen_items:set[tuple[str,str,int]]=set()
		for item in collection:
			item=require_fields(item,{'name','path','line'},f"schema_{collection_name}");key=item[name_key],item['path'],item['line']
			if key in seen_items or freeze_blobs is None or item['path']not in freeze_blobs or type(item['line'])is not int or item['line']<1 or item['name']not in freeze_blobs[item['path']].decode('utf-8'):raise VerifyError('SCHEMA_SOURCE_COLLECTION')
			seen_items.add(key)
	traits=section['handwritten_contract_traits']
	if not isinstance(traits,list):raise VerifyError('SCHEMA_TRAITS')
	for item in traits:
		item=require_fields(item,{'trait','path','source_sha256'},'schema_trait')
		if freeze_blobs is None or item['path']not in freeze_blobs or item['source_sha256']!=sha256(freeze_blobs[item['path']])or item['trait']not in{'CanonicalValue','CanonicalMessage','Validate'}or item['trait']not in freeze_blobs[item['path']].decode('utf-8'):raise VerifyError('SCHEMA_TRAIT_SOURCE')
	if section['boundary']!={'json_instance_is_not_schema_definition':True,'nested_canonical_value_is_not_top_level_message':True,'retained_machine_record_is_not_runtime_validation':True}:raise VerifyError('SCHEMA_BOUNDARY')
	counts=section['counts']
	if not isinstance(counts,dict)or counts.get('canonical_messages')!=11 or counts.get('nested_canonical_values')!=len(section['nested_canonical_values'])or counts.get('tagged_enums')!=len(section['tagged_enums'])or counts.get('json_schema_definitions')!=sum(item['kind']=='DEFINITION'for item in json_records)or counts.get('json_instances')!=sum(item['kind']!='DEFINITION'for item in json_records):raise VerifyError('SCHEMA_COUNTS')
def claim_ledger_scaffold(payload:bytes)->bytes:
	try:lines=payload.decode('utf-8').splitlines(keepends=True)
	except UnicodeDecodeError as error:raise VerifyError('CLAIM_LEDGER_UTF8')from error
	return''.join(line for line in lines if not line.startswith('| CL-')).encode('utf-8')
def expected_claim_type(claim_id:str)->str:
	if any(word in claim_id for word in('PUBLICATION','EVIDENCE')):return'EVIDENCE_OR_PUBLICATION'
	if any(word in claim_id for word in('NCP','TRANSPORT','ROUTE','WIRE')):return'INTERFACE_OR_INTEROPERABILITY'
	if any(word in claim_id for word in('FORMAL','MODEL','INVARIANT')):return'FORMAL_OR_MODEL'
	if any(word in claim_id for word in('SECURITY','AUTHORITY','CRYPTO','ACL','REVOCATION','POLICY')):return'SECURITY_OR_AUTHORITY'
	if any(word in claim_id for word in('DEPLOY','LIVE','FIELD')):return'DEPLOYMENT_OR_RUNTIME'
	return'IMPLEMENTATION'
def validate_claim_tier_product(value:Any,freeze_commit:str,freeze_tree:str,freeze_claim_payload:bytes,implementation_claim_payload:bytes,freeze_claim_state_payload:bytes,freeze_claim_state:dict[str,Any])->None:
	record=require_product_identity(value,'haldir.ch-t003.claim-tier-ledger.v1',{'source','tier_vocabulary','policy','records','counts','bidirectional_links','records_sha256','release_boundary'},'claim_tier')
	if record['tier_vocabulary']!=list(TIER_VOCABULARY):raise VerifyError('CLAIM_TIER_VOCABULARY')
	source=require_fields(record['source'],{'freeze_commit','freeze_tree','claim_ledger','prior_active_claims'},'claim_tier_source')
	if source['freeze_commit']!=freeze_commit or source['freeze_tree']!=freeze_tree or source['claim_ledger']!={'path':CLAIM_LEDGER_PATH,'sha256':sha256(implementation_claim_payload),'bytes':len(implementation_claim_payload)}or source['prior_active_claims'].get('path')!=CLAIMS_STATE_PATH or source['prior_active_claims'].get('sha256')!=sha256(freeze_claim_state_payload)or source['prior_active_claims'].get('bytes')!=len(freeze_claim_state_payload):raise VerifyError('CLAIM_TIER_SOURCE')
	if record['policy']!={'status_and_tier_are_distinct':True,'conservative_mapping':{'PROVEN':'VERIFIED','ALL_OTHER_MARKDOWN_STATUSES':'NOT_CLAIMED'},'no_tier_above_verified_assigned':True}:raise VerifyError('CLAIM_TIER_POLICY')
	before_rows=parse_claim_rows(freeze_claim_payload);after_rows=parse_claim_rows(implementation_claim_payload);before={item['id']:item for item in before_rows};after={item['id']:item for item in after_rows}
	if set(before)!=set(after)or{claim_id for claim_id in before if before[claim_id]!=after[claim_id]}!={NARROWED_CLAIM}or claim_ledger_scaffold(freeze_claim_payload)!=claim_ledger_scaffold(implementation_claim_payload):raise VerifyError('CLAIM_LEDGER_SEMANTIC_DELTA')
	target=after[NARROWED_CLAIM]
	if target['status']!='PROVEN'or target['statement']!=NARROWED_CLAIM_STATEMENT:raise VerifyError('CLAIM_NARROWING_LANGUAGE')
	active=set(freeze_claim_state.get('active_claims',[]));non_claimed=set(freeze_claim_state.get('non_claimed_claims',[]));removed=set(freeze_claim_state.get('removed_claims',[]))
	if set(after)!=active|non_claimed|removed or active&non_claimed or active&removed or non_claimed&removed:raise VerifyError('CLAIM_PARTITION')
	records=record['records']
	if not isinstance(records,list)or len(records)!=52:raise VerifyError('CLAIM_TIER_COUNT')
	observed_ids:set[str]=set();verified=0;not_claimed_count=0
	for item in records:
		item=require_fields(item,{'id','statement','status','evidence','statement_sha256','evidence_sha256','lifecycle_disposition','evidence_tier','claim_type','minimum_evidence','observed_evidence_classes','non_substitutes','linked_surfaces','release_qualified','narrowing'},'claim_tier_record');row=after.get(item['id'])
		if row is None or item['id']in observed_ids or any(item[field]!=row[field]for field in('statement','status','evidence','statement_sha256','evidence_sha256'))or item['evidence_tier']!=TIER_BY_STATUS[row['status']]or item['evidence_tier']not in TIER_VOCABULARY or item['release_qualified']is not False or item['claim_type']!=expected_claim_type(item['id'])or item['minimum_evidence']!=MINIMUM_EVIDENCE_BY_CLAIM_TYPE[item['claim_type']]or item['non_substitutes']!=NON_SUBSTITUTES_BY_CLAIM_TYPE[item['claim_type']]or not isinstance(item['observed_evidence_classes'],list)or item['observed_evidence_classes']!=sorted(set(item['observed_evidence_classes']))or not isinstance(item['linked_surfaces'],list)or not item['linked_surfaces']or item['linked_surfaces']!=sorted(set(item['linked_surfaces']))or not all(valid_path(surface)for surface in item['linked_surfaces']):raise VerifyError('CLAIM_TIER_RECORD')
		if item['evidence_tier']=='VERIFIED':
			verified+=1
			if not item['observed_evidence_classes']:raise VerifyError('CLAIM_TIER_EVIDENCE')
		elif item['evidence_tier']=='NOT_CLAIMED':not_claimed_count+=1
		else:raise VerifyError('CLAIM_TIER_ESCALATION')
		expected_disposition='NOT_CLAIMED'if item['id']in non_claimed else'REMOVED'if item['id']in removed else'ACTIVE'
		if item['id']==NARROWED_CLAIM:
			expected_disposition='ACTIVE_NARROWED_PENDING_ACTIVATION'
			if item['narrowing']!={'narrowed':True,'markdown_status_preserved':'PROVEN','generated_tier_preserved':'VERIFIED','scope':'Repository evidence primitives are verified. This does not qualify a release, deployment, DOI, archive, or field result.'}:raise VerifyError('CLAIM_NARROWING_RECORD')
		elif item['narrowing']is not None:raise VerifyError('CLAIM_NARROWING_EXTRA')
		if item['lifecycle_disposition']!=expected_disposition:raise VerifyError('CLAIM_LIFECYCLE_DISPOSITION')
		observed_ids.add(item['id'])
	if observed_ids!=set(after)or verified!=45 or not_claimed_count!=7:raise VerifyError('CLAIM_TIER_PARTITION')
	digest_matches(record['records_sha256'],records,'claim_tier_records');status_counts:dict[str,int]={}
	for item in records:status_counts[item['status']]=status_counts.get(item['status'],0)+1
	if record['counts']!={'claims':52,'by_status':dict(sorted(status_counts.items())),'by_tier':{'NOT_CLAIMED':7,'VERIFIED':45},'narrowed':1,'release_qualified':0}:raise VerifyError('CLAIM_TIER_COUNTS')
	boundary=record['release_boundary']
	if not isinstance(boundary,dict)or boundary.get('overall_status')!='NO_GO'or boundary.get('release_qualified_claims')!=[]or any(boundary.get(field)is not False for field in('archive_authorized','doi_authorized','github_release_authorized','tag_authorized','zenodo_authorized')):raise VerifyError('CLAIM_RELEASE_BOUNDARY')
	links=require_fields(record['bidirectional_links'],{'claim_to_surface_complete','surface_to_claims','surface_to_claims_sha256'},'claim_bidirectional_links')
	if links['claim_to_surface_complete']is not True:raise VerifyError('CLAIM_LINK_COMPLETENESS')
	reverse=links['surface_to_claims']
	if not isinstance(reverse,list):raise VerifyError('CLAIM_REVERSE_LINKS')
	reverse_map:dict[str,list[str]]={}
	for item in reverse:
		item=require_fields(item,{'surface','claim_ids'},'surface_claim_link')
		if item['surface']in reverse_map or not isinstance(item['surface'],str)or not item['surface']or not isinstance(item['claim_ids'],list)or not item['claim_ids']or item['claim_ids']!=sorted(set(item['claim_ids']))or not set(item['claim_ids']).issubset(observed_ids):raise VerifyError('CLAIM_REVERSE_LINK')
		reverse_map[item['surface']]=item['claim_ids']
	digest_matches(links['surface_to_claims_sha256'],reverse,'surface_to_claims')
	for item in records:
		for surface in item['linked_surfaces']:
			if item['id']not in reverse_map.get(surface,[]):raise VerifyError('CLAIM_LINK_DANGLING')
	expected_reverse:dict[str,list[str]]={}
	for item in records:
		for surface in item['linked_surfaces']:expected_reverse.setdefault(surface,[]).append(item['id'])
	if reverse!=[{'surface':surface,'claim_ids':sorted(identifiers)}for(surface,identifiers)in sorted(expected_reverse.items())]:raise VerifyError('CLAIM_REVERSE_LINK_MISMATCH')
def scan_claim_language_text(payload:bytes,pattern:re.Pattern[str],scope:str,path:str|None,member:str|None,endpoint:str|None)->list[dict[str,Any]]:
	try:text=payload.decode('utf-8')
	except UnicodeDecodeError:return[]
	hits:list[dict[str,Any]]=[]
	for(line_number,line)in enumerate(text.splitlines(),start=1):
		line_digest=sha256(line.encode('utf-8'));identifiers=sorted(set(CLAIM_PATTERN.findall(line)))
		for match in pattern.finditer(line):hits.append({'scope':scope,'path':path,'member':member,'endpoint':endpoint,'line':line_number,'column':match.start()+1,'match':match.group(0),'normalized_term':re.sub('[-\\s]+',' ',match.group(0).casefold()),'claim_ids':identifiers,'line_sha256':line_digest})
	return hits
def extract_archive_payloads(path:str,payload:bytes)->dict[str,bytes]:
	'Return exact member bytes after inspect_archive has accepted the input.';inspect_archive(path,payload)
	if path.casefold().endswith('.gz'):inflater=zlib.decompressobj(16+zlib.MAX_WBITS);expanded=inflater.decompress(payload,MAX_ARCHIVE_MEMBER_BYTES+1);return{PurePosixPath(path).name.removesuffix('.gz'):expanded}
	with zipfile.ZipFile(io.BytesIO(payload),'r')as archive:return{item.filename:archive.read(item)for item in archive.infolist()if not item.is_dir()}
def expected_claim_language_product(freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],candidate_claim_payload:bytes,public_inventory:dict[str,Any],github_metadata:dict[str,Any])->tuple[list[dict[str,Any]],list[dict[str,Any]]]:
	sources:list[dict[str,Any]]=[];hits:list[dict[str,Any]]=[]
	for entry in freeze_entries:
		path=entry['path'];payload=freeze_blobs[path];kind=content_kind(path,payload);sources.append({'scope':'TRACKED','path':path,'member':None,'endpoint':None,'sha256':sha256(payload),'bytes':len(payload),'content_kind':kind})
		if path.casefold().endswith(('.md','.rst','.txt')):hits.extend(scan_claim_language_text(payload,BASELINE_CLAIM_REGEX,'HANDOFF_BASELINE_TRACKED_TEXT',path,None,None))
		if kind=='UTF8'and path!=CLAIM_LEDGER_PATH:hits.extend(scan_claim_language_text(payload,EXTENDED_CLAIM_REGEX,'EXTENDED_TRACKED_UTF8',path,None,None))
	sources.append({'scope':'CANDIDATE_CLAIM_LEDGER','path':CLAIM_LEDGER_PATH,'member':None,'endpoint':None,'sha256':sha256(candidate_claim_payload),'bytes':len(candidate_claim_payload),'content_kind':'UTF8'});hits.extend(scan_claim_language_text(candidate_claim_payload,EXTENDED_CLAIM_REGEX,'EXTENDED_CANDIDATE_CLAIM_LEDGER_UTF8',CLAIM_LEDGER_PATH,None,None))
	for archive in public_inventory['archives']:
		path=archive['path'];contents=extract_archive_payloads(path,freeze_blobs[path])
		for member in archive['members']:
			name=member['name'];payload=contents.get(name)
			if payload is None or len(payload)!=member['bytes']or sha256(payload)!=member['sha256']:raise VerifyError('CLAIM_LANGUAGE_ARCHIVE_BINDING')
			sources.append({'scope':'ARCHIVE_MEMBER','path':path,'member':name,'endpoint':None,'sha256':member['sha256'],'bytes':member['bytes'],'content_kind':member['content_kind']})
			if member['content_kind']=='UTF8':hits.extend(scan_claim_language_text(payload,EXTENDED_CLAIM_REGEX,'EXTENDED_ARCHIVE_MEMBER_UTF8',path,name,None))
	for observation in public_inventory['cli']['runtime_observations']:
		for stream in('stdout','stderr'):payload=observation[stream].encode('utf-8');channel=f"{observation["scenario"]}:{stream}";sources.append({'scope':'CLI_RUNTIME','path':None,'member':None,'endpoint':channel,'sha256':sha256(payload),'bytes':len(payload),'content_kind':'UTF8'});hits.extend(scan_claim_language_text(payload,EXTENDED_CLAIM_REGEX,'EXTENDED_CLI_RUNTIME_UTF8',None,None,channel))
	normalized=required_subset(github_metadata['normalized'],{'repository'},'github_normalized');repository=required_subset(normalized['repository'],{'description'},'github_normalized_repository');description=repository['description'];description_payload=description.encode('utf-8')if isinstance(description,str)else b'';github_endpoint='https://github.com/sepahead/haldir';sources.append({'scope':'GITHUB_DESCRIPTION','path':None,'member':None,'endpoint':github_endpoint,'sha256':sha256(description_payload),'bytes':len(description_payload),'content_kind':'UTF8'if description_payload else'ABSENT'})
	if description_payload:hits.extend(scan_claim_language_text(description_payload,EXTENDED_CLAIM_REGEX,'EXTENDED_GITHUB_DESCRIPTION_UTF8',None,None,github_endpoint))
	sources.sort(key=lambda item:(item['scope'],item['path']or'',item['member']or'',item['endpoint']or''));hits.sort(key=lambda item:(item['scope'],item['path']or'',item['member']or'',item['endpoint']or'',item['line'],item['column'],item['match']));return sources,hits
def validate_claim_language_product(value:Any,freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],candidate_claim_payload:bytes,public_inventory:dict[str,Any],github_metadata:dict[str,Any])->None:
	record=require_product_identity(value,'haldir.ch-t003.claim-language.v1',{'source','policy','sources','hits','counts','hits_sha256'},'claim_language');required_pattern='(?i)\\b(safe|secure|verified|validated|production[- ]ready|field[- ]tested|exact|identical|complete|correct|real[- ]time|certified|compatible|stable|proven|guarantee)\\b'
	if not isinstance(record['policy'],dict)or record['policy'].get('baseline_pattern')!=required_pattern:raise VerifyError('CLAIM_LANGUAGE_POLICY')
	sources=record['sources'];hits=record['hits']
	if not isinstance(sources,list)or not isinstance(hits,list):raise VerifyError('CLAIM_LANGUAGE_SHAPE')
	source_keys:set[tuple[Any,Any,Any,Any]]=set()
	for source in sources:
		source=require_fields(source,{'scope','path','member','endpoint','sha256','bytes','content_kind'},'claim_language_source');key=source['scope'],source['path'],source['member'],source['endpoint']
		if key in source_keys or not isinstance(source['scope'],str)or not source['scope']or source['path']is not None and(not isinstance(source['path'],str)or not valid_path(source['path']))or re.fullmatch('[0-9a-f]{64}',source['sha256'])is None or type(source['bytes'])is not int or source['bytes']<0 or source['content_kind']not in{'ABSENT','BINARY','UTF8'}or source['content_kind']=='ABSENT'and(source['bytes']!=0 or source['sha256']!=sha256(b'')):raise VerifyError('CLAIM_LANGUAGE_SOURCE')
		source_keys.add(key)
	for hit in hits:
		hit=require_fields(hit,{'scope','path','member','endpoint','line','column','match','normalized_term','claim_ids','line_sha256'},'claim_language_hit')
		if type(hit['line'])is not int or hit['line']<1 or type(hit['column'])is not int or hit['column']<1 or not isinstance(hit['match'],str)or not hit['match']or not isinstance(hit['normalized_term'],str)or not hit['normalized_term']or not isinstance(hit['claim_ids'],list)or hit['claim_ids']!=sorted(set(hit['claim_ids']))or re.fullmatch('[0-9a-f]{64}',hit['line_sha256'])is None:raise VerifyError('CLAIM_LANGUAGE_HIT')
	expected_paths,expected_baseline,expected_lines=expected_baseline_language_hits(freeze_entries,freeze_blobs);expected_sources,expected_hits=expected_claim_language_product(freeze_entries,freeze_blobs,candidate_claim_payload,public_inventory,github_metadata);expected_source_record={'freeze_commit':public_inventory['source']['freeze_commit'],'freeze_tree':public_inventory['source']['freeze_tree'],'records_sha256':sha256(canonical_json([item for item in expected_sources if item['scope']=='TRACKED'])),'archives_sha256':sha256(canonical_json([item for item in expected_sources if item['scope']=='ARCHIVE_MEMBER'])),'cli_runtime_sha256':sha256(canonical_json([item for item in expected_sources if item['scope']=='CLI_RUNTIME'])),'github_description_sha256':next(item['sha256']for item in expected_sources if item['scope']=='GITHUB_DESCRIPTION')};baseline=[item for item in hits if item['scope']=='HANDOFF_BASELINE_TRACKED_TEXT']
	if record['source']!=expected_source_record or sources!=expected_sources or hits!=expected_hits or baseline!=expected_baseline or len(expected_paths)!=49 or len(expected_baseline)!=1379 or expected_lines!=1181:raise VerifyError('CLAIM_LANGUAGE_BASELINE')
	counts=record['counts']
	if not isinstance(counts,dict)or counts.get('sources')!=len(sources)or counts.get('hits')!=len(hits)or counts.get('baseline_hits')!=len(baseline)or type(counts.get('extended_hits'))is not int or counts['extended_hits']!=len(hits)-len(baseline)or counts.get('tracked_hits')!=sum('TRACKED'in item['scope']for item in hits)or counts.get('archive_hits')!=sum('ARCHIVE'in item['scope']for item in hits)or counts.get('cli_hits')!=sum('CLI'in item['scope']for item in hits)or counts.get('github_hits')!=sum('GITHUB'in item['scope']for item in hits)or counts.get('files_or_channels')!=len({(item['scope'],item['path'],item['member'],item['endpoint'])for item in hits}):raise VerifyError('CLAIM_LANGUAGE_COUNTS')
	digest_matches(record['hits_sha256'],hits,'claim_language_hits')
REQUIRED_GITHUB_ENDPOINT_FRAGMENTS='/repos/sepahead/haldir','/topics','/community/profile','/license','/languages','/contributors','/branches','/branches/main/protection','/rulesets','/tags','/releases','/actions/workflows','/actions/permissions','/actions/permissions/workflow','/environments','/actions/variables','/actions/secrets','/pages','/vulnerability-alerts','/private-vulnerability-reporting','/hooks','/keys','/autolinks'
SENSITIVE_RAW_BODY_ENDPOINTS={'autolinks','deploy_keys','hooks','secrets','variables'}
GITHUB_ENDPOINT_SPECS=('repository','/repos/sepahead/haldir',False,{200}),('topics','/repos/sepahead/haldir/topics',False,{200}),('community_profile','/repos/sepahead/haldir/community/profile',False,{200}),('license','/repos/sepahead/haldir/license',False,{200}),('languages','/repos/sepahead/haldir/languages',False,{200}),('contributors','/repos/sepahead/haldir/contributors?per_page=100&anon=1',True,{200}),('branches','/repos/sepahead/haldir/branches?per_page=100',True,{200}),('main_protection','/repos/sepahead/haldir/branches/main/protection',False,{200,404}),('rulesets','/repos/sepahead/haldir/rulesets?per_page=100',True,{200,404}),('tags','/repos/sepahead/haldir/tags?per_page=100',True,{200}),('releases','/repos/sepahead/haldir/releases?per_page=100',True,{200}),('workflows','/repos/sepahead/haldir/actions/workflows?per_page=100',True,{200}),('actions_permissions','/repos/sepahead/haldir/actions/permissions',False,{200}),('workflow_token_permissions','/repos/sepahead/haldir/actions/permissions/workflow',False,{200}),('environments','/repos/sepahead/haldir/environments?per_page=100',True,{200,404}),('variables','/repos/sepahead/haldir/actions/variables?per_page=100',True,{200,404}),('secrets','/repos/sepahead/haldir/actions/secrets?per_page=100',True,{200,404}),('pages','/repos/sepahead/haldir/pages',False,{200,404}),('vulnerability_alerts','/repos/sepahead/haldir/vulnerability-alerts',False,{204,404}),('private_vulnerability_reporting','/repos/sepahead/haldir/private-vulnerability-reporting',False,{200,404}),('code_scanning_default_setup','/repos/sepahead/haldir/code-scanning/default-setup',False,{200,404}),('hooks','/repos/sepahead/haldir/hooks?per_page=100',True,{200}),('deploy_keys','/repos/sepahead/haldir/keys?per_page=100',True,{200}),('autolinks','/repos/sepahead/haldir/autolinks?per_page=100',True,{200}),('interaction_limits','/repos/sepahead/haldir/interaction-limits',False,{200,204,404})
def validate_github_metadata_v2(value:Any,freeze_commit:str,freeze_time:datetime,implementation_time:datetime)->None:
	record=require_product_identity(value,'haldir.ch-t003.github-metadata.v1',{'captured_at_utc','repository','request_policy','captures','endpoint_summary','normalized','captures_sha256'},'github_metadata');captured=parse_utc(record['captured_at_utc'])
	if not freeze_time<=captured<=implementation_time:raise VerifyError('GITHUB_CHRONOLOGY')
	if record['request_policy']!={'method':'GET','accept':'application/vnd.github+json','api_version':'2022-11-28','authentication':'BEARER_TOKEN_USED_NOT_RETAINED','pagination':'FOLLOW_REL_NEXT_TO_CLOSURE','per_page':100,'raw_body':'OMITTED_FOR_SENSITIVE_ENDPOINTS_OTHERWISE_DIGEST_AND_SIZE','retained_document':'CANONICAL_JSON_DIGEST_AND_SIZE','sensitive_values':'FIELD_LEVEL_REDACTION'}:raise VerifyError('GITHUB_REQUEST_POLICY')
	captures=record['captures']
	if not isinstance(captures,list)or not captures:raise VerifyError('GITHUB_CAPTURES')
	capture_ids:set[str]=set();endpoint_pages:set[tuple[str,int]]=set();endpoint_texts:list[str]=[];grouped_captures:dict[str,list[dict[str,Any]]]={identifier:[]for(identifier,_endpoint,_paginated,_statuses)in GITHUB_ENDPOINT_SPECS}
	for capture in captures:
		capture=require_fields(capture,{'id','endpoint','page','method','accept','api_version','http_status','etag','link','bytes','sha256','document_bytes','document_sha256','disposition','redaction','document'},'github_capture');identifier_match=re.fullmatch('([a-z0-9_]+)#page-(\\d{4})',capture['id']);endpoint_identifier=identifier_match.group(1)if identifier_match is not None else None;endpoint_page=endpoint_identifier,capture['page'];expected_disposition={200:'OBSERVED',204:'ENABLED_OR_EMPTY_NO_CONTENT',404:'ABSENT_DISABLED_OR_NOT_CONFIGURED'}.get(capture['http_status']);raw_body_retained=endpoint_identifier not in SENSITIVE_RAW_BODY_ENDPOINTS
		if capture['id']in capture_ids or endpoint_page in endpoint_pages or endpoint_identifier not in grouped_captures or int(identifier_match.group(2))!=capture['page']or not isinstance(capture['endpoint'],str)or not capture['endpoint'].startswith('/repos/sepahead/haldir')or type(capture['page'])is not int or capture['page']<1 or capture['method']!='GET'or capture['accept']!='application/vnd.github+json'or capture['api_version']!='2022-11-28'or capture['http_status']not in{200,204,404}or not raw_body_retained and(capture['etag']is not None or capture['link']is not None)or capture['etag']is not None and not isinstance(capture['etag'],str)or capture['link']is not None and not isinstance(capture['link'],str)or raw_body_retained and(type(capture['bytes'])is not int or not 0<=capture['bytes']<=1048576 or re.fullmatch('[0-9a-f]{64}',capture['sha256'])is None)or not raw_body_retained and(capture['bytes']is not None or capture['sha256']is not None)or type(capture['document_bytes'])is not int or not 0<=capture['document_bytes']<=1048576 or re.fullmatch('[0-9a-f]{64}',capture['document_sha256'])is None or not isinstance(capture['disposition'],str)or not capture['disposition']or not isinstance(capture['redaction'],list)or not all(isinstance(item,str)for item in capture['redaction'])or capture['disposition']!=expected_disposition:raise VerifyError('GITHUB_CAPTURE_POLICY')
		retained_document=canonical_json(capture['document'])
		if capture['document_bytes']!=len(retained_document)or capture['document_sha256']!=sha256(retained_document):raise VerifyError('GITHUB_CAPTURE_BODY')
		if capture['http_status']==204 and capture['document']is not None:raise VerifyError('GITHUB_NO_CONTENT')
		if endpoint_identifier in SENSITIVE_RAW_BODY_ENDPOINTS and capture['http_status']!=200 and capture['document']is not None:raise VerifyError('GITHUB_SENSITIVE_ABSENCE')
		if endpoint_identifier in{'hooks','deploy_keys','autolinks'}:
			document=capture['document']
			if not isinstance(document,list)or any(item!={'present':True}for item in document):raise VerifyError('GITHUB_PRESENCE_ONLY')
			if capture['redaction']!=[f"/{index}/*"for index in range(len(document))]:raise VerifyError('GITHUB_PRESENCE_ONLY')
		if endpoint_identifier=='secrets'and capture['http_status']==200:
			document=capture['document']
			if not isinstance(document,dict)or set(document)!={'total_count','secrets'}:raise VerifyError('GITHUB_SECRET_REDACTION')
			safe_keys={'name','created_at','updated_at'}
			if type(document['total_count'])is not int or document['total_count']<0 or not isinstance(document['secrets'],list)or any(not isinstance(item,dict)or not set(item).issubset(safe_keys)or'name'not in item or not isinstance(item['name'],str)or not item['name']or any(key in item and not isinstance(item[key],str)for key in('created_at','updated_at'))for item in document['secrets']):raise VerifyError('GITHUB_SECRET_REDACTION')
		if endpoint_identifier=='variables'and capture['http_status']==200:
			document=capture['document']
			if not isinstance(document,dict)or set(document)!={'total_count','variables'}:raise VerifyError('GITHUB_VARIABLE_REDACTION')
			safe_keys={'name','created_at','updated_at'}
			if type(document['total_count'])is not int or document['total_count']<0 or not isinstance(document['variables'],list)or any(not isinstance(item,dict)or not set(item).issubset(safe_keys)or'name'not in item or not isinstance(item['name'],str)or not item['name']or any(key in item and not isinstance(item[key],str)for key in('created_at','updated_at'))for item in document['variables']):raise VerifyError('GITHUB_VARIABLE_REDACTION')
			expected_redactions=[f"/variables/{index}/value"for index in range(len(document['variables']))]
			if capture['redaction']!=expected_redactions:raise VerifyError('GITHUB_VARIABLE_REDACTION')
		capture_ids.add(capture['id']);endpoint_pages.add(endpoint_page);endpoint_texts.append(capture['endpoint']);grouped_captures[endpoint_identifier].append(capture)
	endpoints_joined='\n'.join(endpoint_texts)
	if any(fragment not in endpoints_joined for fragment in REQUIRED_GITHUB_ENDPOINT_FRAGMENTS):raise VerifyError('GITHUB_ENDPOINT_CLOSURE')
	expected_capture_ids:list[str]=[];expected_summaries:list[dict[str,Any]]=[]
	for(identifier,endpoint,paginated,allowed_statuses)in GITHUB_ENDPOINT_SPECS:
		group=grouped_captures[identifier]
		if not group:raise VerifyError('GITHUB_ENDPOINT_MISSING')
		pages=[item['page']for item in group]
		if pages!=list(range(1,len(group)+1)):raise VerifyError('GITHUB_PAGE_SEQUENCE')
		if any(item['http_status']not in allowed_statuses for item in group):raise VerifyError('GITHUB_ENDPOINT_STATUS')
		base=urllib.parse.urlparse('https://api.github.com'+endpoint);base_query=urllib.parse.parse_qsl(base.query,keep_blank_values=True)
		for(index,item)in enumerate(group):
			expected_query=base_query+([]if index==0 else[('page',str(index+1))]);expected_endpoint=base.path+(f"?{urllib.parse.urlencode(expected_query)}"if expected_query else'')
			if item['endpoint']!=expected_endpoint:raise VerifyError('GITHUB_ENDPOINT_SEQUENCE')
		if not paginated and len(group)!=1:raise VerifyError('GITHUB_UNEXPECTED_PAGINATION')
		for(index,item)in enumerate(group):
			expected_capture_ids.append(f"{identifier}#page-{index+1:04d}")
			if identifier in SENSITIVE_RAW_BODY_ENDPOINTS:continue
			next_match=re.search('<([^>]+)>;\\s*rel="next"',item['link'])if isinstance(item['link'],str)else None
			if index+1<len(group):
				if next_match is None:raise VerifyError('GITHUB_PAGE_LINK_MISSING')
				parsed=urllib.parse.urlparse(next_match.group(1));next_endpoint=parsed.path+(f"?{parsed.query}"if parsed.query else'')
				if parsed.scheme!='https'or parsed.netloc!='api.github.com'or next_endpoint!=group[index+1]['endpoint']:raise VerifyError('GITHUB_PAGE_LINK')
			elif next_match is not None:raise VerifyError('GITHUB_PAGE_LINK_TRAILING')
		expected_summaries.append({'id':identifier,'endpoint':endpoint,'pages':len(group),'http_statuses':[item['http_status']for item in group],'disposition':group[-1]['disposition'],'complete':True})
	if[item['id']for item in captures]!=expected_capture_ids:raise VerifyError('GITHUB_CAPTURE_ORDER')
	summaries=record['endpoint_summary']
	if summaries!=expected_summaries:raise VerifyError('GITHUB_ENDPOINT_SUMMARY')
	digest_matches(record['captures_sha256'],captures,'github_captures');repository=require_fields(record['repository'],{'owner','name','full_name','default_branch'},'github_repository')
	if repository!={'owner':'sepahead','name':'haldir','full_name':'sepahead/haldir','default_branch':'main'}:raise VerifyError('GITHUB_REPOSITORY_IDENTITY')
	normalized_text=canonical_json(record['normalized']).decode('utf-8')
	for token in('"tag_count":0','"release_count":0','"private":false','"archived":false','"disabled":false','"default_branch":"main"','"owner":"sepahead"'):
		if token not in normalized_text:raise VerifyError('GITHUB_NORMALIZED_STATE')
	normalized=record['normalized']
	if not isinstance(normalized,dict)or normalized.get('default_branch_head')!=freeze_commit or normalized.get('publication')!={'tag_count':0,'release_count':0,'tags':[],'releases':[]}or normalized.get('completeness')!={'expected_endpoint_ids':[item[0]for item in GITHUB_ENDPOINT_SPECS],'captured_endpoint_ids':[item[0]for item in GITHUB_ENDPOINT_SPECS],'all_complete':True,'permission_denied':[]}:raise VerifyError('GITHUB_NORMALIZED_BINDING')
	for identifier in('hooks','deploy_keys','autolinks'):
		documents=[item['document']for item in grouped_captures[identifier]if isinstance(item['document'],list)];count=sum(len(item)for item in documents)
		if normalized.get(identifier)!={'count':count,'present':count>0}:raise VerifyError('GITHUB_PRESENCE_NORMALIZED')
def validate_review_overlay(value:Any,repo:Path,freeze_commit:str,freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],implementation_entries:list[dict[str,Any]],implementation_blobs:dict[str,bytes])->None:
	record=require_product_identity(value,'haldir.ch-t003.file-review-overlay.v1',{'source','coverage_policy','prior_artifacts','freeze_records','candidate_records','partition','counts','digests'},'review_overlay');freeze_tree=commit_meta(repo,freeze_commit)['tree']
	if record['source']!={'freeze_commit':freeze_commit,'freeze_tree':freeze_tree,'prior_activation_commit':PRIOR_ACTIVATION}:raise VerifyError('REVIEW_SOURCE')
	if record['coverage_policy']!={'unit':'EXACT_REGULAR_GIT_BLOB_PATH_AND_CONTENT','freeze_coverage':'EVERY_F_BLOB','candidate_coverage':'EXACT_I_DIFF_PLAN','qualification_timing':'NO_C_REVIEW_IS_CLAIMED_IN_I','named_human_review_claimed':False}:raise VerifyError('REVIEW_COVERAGE_POLICY')
	prior_paths=['audit/generated/FILE_REVIEW_LEDGER.csv','audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json','release/0.9.0/current-head/tasks/ch-t002/e0002/evidence/file-review-packet-manifest.json','release/0.9.0/current-head/tasks/ch-t002/e0002/qualification.json','release/0.9.0/current-head/tasks/ch-t002/e0002/activation.json'];freeze_map={item['path']:item for item in freeze_entries};expected_prior=[]
	for path in prior_paths:entry=freeze_map[path];payload=freeze_blobs[path];expected_prior.append({'path':path,'git_mode':entry['git_mode'],'git_object_id':entry['git_object_id'],'bytes':len(payload),'sha256':sha256(payload),'role':'PRIOR_REVIEW_OR_LIFECYCLE_EVIDENCE'})
	if record['prior_artifacts']!=expected_prior:raise VerifyError('REVIEW_PRIOR_ARTIFACTS')
	try:ledger_text=freeze_blobs[prior_paths[0]].decode('utf-8')
	except UnicodeDecodeError as error:raise VerifyError('REVIEW_PRIOR_LEDGER_UTF8')from error
	ledger_reader=csv.DictReader(io.StringIO(ledger_text),strict=True);ledger_digests={row['path']:row['sha256']for row in ledger_reader if isinstance(row.get('path'),str)and isinstance(row.get('sha256'),str)};prior_overlay=load_json(freeze_blobs[prior_paths[1]],canonical=False);prior_entries=prior_overlay.get('entries')if isinstance(prior_overlay,dict)else None
	if not isinstance(prior_entries,list):raise VerifyError('REVIEW_PRIOR_OVERLAY')
	overlay_digests={item['path']:item['sha256']for item in prior_entries if isinstance(item,dict)and isinstance(item.get('path'),str)and isinstance(item.get('sha256'),str)};freeze_delta={REGISTRY_PATH,FREEZE_PATH,TESTS_PATH,VERIFIER_PATH};freeze_records=record['freeze_records']
	if not isinstance(freeze_records,list)or len(freeze_records)!=426:raise VerifyError('REVIEW_FREEZE_COUNT')
	for(item,entry)in zip(freeze_records,freeze_entries,strict=True):
		item=require_fields(item,{'path','git_mode','git_object_id','bytes','sha256','source_review_basis','assigned_review','review_status'},'review_freeze_record');payload=freeze_blobs[entry['path']];expected_basis='PRIOR_SIGNED_ACTIVATION_TREE'
		if entry['path']in freeze_delta:expected_basis='CH_T003_SIGNED_FREEZE_PROTOCOL'
		elif ledger_digests.get(entry['path'])==sha256(payload):expected_basis='CH_T001_BASE_REVIEW_LEDGER_EXACT_CONTENT'
		elif overlay_digests.get(entry['path'])==sha256(payload):expected_basis='CH_T002_REVIEW_OVERLAY_EXACT_CONTENT'
		if item['path']!=entry['path']or item['git_mode']!=entry['git_mode']or item['git_object_id']!=entry['git_object_id']or item['bytes']!=len(payload)or item['sha256']!=sha256(payload)or item['source_review_basis']!=expected_basis or item['assigned_review']!='CH-T003-C-INDEPENDENT-QUALIFICATION'or item['review_status']!='C_REVIEW_REQUIRED':raise VerifyError('REVIEW_FREEZE_RECORD')
	candidates=record['candidate_records']
	if not isinstance(candidates,list)or len(candidates)!=9:raise VerifyError('REVIEW_CANDIDATE_COUNT')
	implementation_map={item['path']:item for item in implementation_entries};cyclic_outputs={CLAIM_TIER_PATH,REVIEW_OVERLAY_PATH,GITHUB_METADATA_PATH,LEDGER_COMPOSITION_PATH,PUBLIC_INVENTORY_PATH,CLAIM_LANGUAGE_PATH}
	for(item,path)in zip(candidates,IMPLEMENTATION_PLAN,strict=True):
		item=require_fields(item,{'path','change','binding_kind','sha256','bytes','assigned_review','review_status'},'review_candidate_record')
		if item['path']!=path or item['change']!=IMPLEMENTATION_PLAN[path]or item['assigned_review']!='CH-T003-C-INDEPENDENT-QUALIFICATION'or item['review_status']!='C_REVIEW_REQUIRED':raise VerifyError('REVIEW_CANDIDATE_RECORD')
		if path in cyclic_outputs:
			if item['binding_kind']!='NO_INNER_DIGEST'or item['sha256']is not None or item['bytes']is not None:raise VerifyError('REVIEW_CANDIDATE_CYCLE')
		else:
			entry=implementation_map[path];payload=implementation_blobs[path]
			if item['binding_kind']!='EXACT_CANDIDATE_BYTES'or item['sha256']!=sha256(payload)or item['bytes']!=len(payload)or entry['git_object_type']!='blob':raise VerifyError('REVIEW_CANDIDATE_IDENTITY')
	partition=require_fields(record['partition'],{'freeze_commit','freeze_tree','freeze_count','freeze_paths_sha256','candidate_count','candidate_added','candidate_modified','candidate_paths_sha256','expected_implementation_count','disjoint_additions','added_paths'},'review_partition');freeze_paths=[item['path']for item in freeze_records];candidate_paths=[item['path']for item in candidates];added_paths=sorted(path for(path,status)in IMPLEMENTATION_PLAN.items()if status=='A')
	if partition['freeze_commit']!=freeze_commit or partition['freeze_tree']!=freeze_tree or partition['freeze_count']!=426 or partition['freeze_paths_sha256']!=sha256(canonical_json(freeze_paths))or partition['candidate_count']!=9 or partition['candidate_added']!=8 or partition['candidate_modified']!=1 or partition['candidate_paths_sha256']!=sha256(canonical_json(candidate_paths))or partition['expected_implementation_count']!=434 or partition['disjoint_additions']is not True or partition['added_paths']!=added_paths:raise VerifyError('REVIEW_PARTITION')
	counts=record['counts'];exact_content=sum(item['source_review_basis'].endswith('EXACT_CONTENT')for item in freeze_records)
	if counts!={'freeze_records':426,'candidate_records':9,'implementation_records':434,'prior_exact_content_bindings':exact_content,'freeze_protocol_records':4,'c_review_pending':435}:raise VerifyError('REVIEW_COUNTS')
	if record['digests']!={'prior_artifacts_sha256':sha256(canonical_json(expected_prior)),'freeze_records_sha256':sha256(canonical_json(freeze_records)),'candidate_records_sha256':sha256(canonical_json(candidates)),'partition_sha256':sha256(canonical_json(partition))}:raise VerifyError('REVIEW_DIGESTS')
def validate_ledger_composition_v2(value:Any,repo:Path,freeze_commit:str,freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],implementation_commit:str,implementation_entries:list[dict[str,Any]],implementation_blobs:dict[str,bytes])->None:
	record=require_product_identity(value,'haldir.ch-t003.ledger-composition.v1',{'prior_lifecycle','source','artifacts','coverage','review_boundary','bidirectional_references'},'ledger_composition')
	if record['prior_lifecycle']!={'freeze_commit':PRIOR_FREEZE,'implementation_commit':PRIOR_IMPLEMENTATION,'qualification_commit':PRIOR_QUALIFICATION,'activation_commit':PRIOR_ACTIVATION}:raise VerifyError('COMPOSITION_PRIOR_LIFECYCLE')
	source=require_fields(record['source'],{'freeze_commit','freeze_tree','composition_path','self_digest_omitted'},'composition_source')
	if source!={'freeze_commit':freeze_commit,'freeze_tree':commit_meta(repo,freeze_commit)['tree'],'composition_path':LEDGER_COMPOSITION_PATH,'self_digest_omitted':True}:raise VerifyError('COMPOSITION_SOURCE')
	public=load_json(implementation_blobs[PUBLIC_INVENTORY_PATH]);public_records=public['records'];candidate_records=public['candidate_implementation']['records'];coverage=require_fields(record['coverage'],{'freeze_partition','candidate_partition','review_overlay','sibling_products'},'composition_coverage');freeze_partition=required_subset(coverage['freeze_partition'],{'count','commit','tree','paths_sha256','records_sha256'},'composition_freeze_partition');candidate_partition=require_fields(coverage['candidate_partition'],{'count','added','modified','paths_sha256','records_sha256','expected_implementation_count'},'composition_candidate_partition')
	if freeze_partition!={'count':426,'commit':freeze_commit,'tree':commit_meta(repo,freeze_commit)['tree'],'paths_sha256':sha256(canonical_json([item['path']for item in freeze_entries])),'records_sha256':sha256(canonical_json(public_records))}or candidate_partition['count']!=9 or candidate_partition['added']!=8 or candidate_partition['modified']!=1 or candidate_partition['expected_implementation_count']!=434 or candidate_partition['paths_sha256']!=sha256(canonical_json(list(IMPLEMENTATION_PLAN)))or candidate_partition['records_sha256']!=sha256(canonical_json(candidate_records)):raise VerifyError('COMPOSITION_PARTITION_COUNTS')
	overlay=require_fields(coverage['review_overlay'],{'path','sha256','bytes'},'composition_overlay');overlay_payload=implementation_blobs[REVIEW_OVERLAY_PATH]
	if overlay!={'path':REVIEW_OVERLAY_PATH,'sha256':sha256(overlay_payload),'bytes':len(overlay_payload)}:raise VerifyError('COMPOSITION_OVERLAY_IDENTITY')
	siblings=require_fields(coverage['sibling_products'],{'count','paths','paths_sha256'},'composition_siblings');sibling_paths=sorted({CLAIM_TIER_PATH,REVIEW_OVERLAY_PATH,GITHUB_METADATA_PATH,PUBLIC_INVENTORY_PATH,CLAIM_LANGUAGE_PATH})
	if siblings['count']!=5 or siblings['paths']!=sibling_paths or siblings['paths_sha256']!=sha256(canonical_json(sibling_paths)):raise VerifyError('COMPOSITION_SIBLINGS')
	boundary=record['review_boundary']
	if not isinstance(boundary,dict)or boundary.get('automated_review_only')is not True or boundary.get('review_completed_at_i')is not False or boundary.get('review_required_at_c')is not True or boundary.get('retroactive_ch_t002_subject_claim')is not False:raise VerifyError('COMPOSITION_REVIEW_BOUNDARY')
	prior_paths=['audit/generated/FILE_REVIEW_LEDGER.csv','audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json','release/0.9.0/current-head/tasks/ch-t002/e0002/evidence/file-review-packet-manifest.json','release/0.9.0/current-head/tasks/ch-t002/e0002/qualification.json','release/0.9.0/current-head/tasks/ch-t002/e0002/activation.json'];freeze_map={item['path']:item for item in freeze_entries};expected_artifacts:list[dict[str,Any]]=[]
	for path in prior_paths:entry=freeze_map[path];payload=freeze_blobs[path];expected_artifacts.append({'path':path,'git_mode':entry['git_mode'],'git_object_id':entry['git_object_id'],'bytes':len(payload),'sha256':sha256(payload),'role':'PRIOR_REVIEW_OR_LIFECYCLE_EVIDENCE'})
	for path in sibling_paths:payload=implementation_blobs[path];expected_artifacts.append({'path':path,'bytes':len(payload),'sha256':sha256(payload),'role':'CH_T003_GENERATED_SIBLING_PRODUCT'})
	if record['artifacts']!=expected_artifacts:raise VerifyError('COMPOSITION_ARTIFACTS')
	if record['bidirectional_references']!={'overlay_lists_every_freeze_path':True,'overlay_lists_exact_candidate_plan':True,'sibling_artifacts_match_expected_set':True}:raise VerifyError('COMPOSITION_REFERENCES')
	implementation_paths=[item['path']for item in implementation_entries]
	if len(implementation_entries)!=434 or sha256(canonical_json(implementation_paths))!='8a4264751b96c8b1494d4397f143ad3b4e9a13ca8ee5ab53e0a335a738274ff0':raise VerifyError('COMPOSITION_IMPLEMENTATION_COUNT')
def validate_cargo_inventory(value:Any,freeze_blobs:dict[str,bytes])->list[dict[str,Any]]:
	section=require_fields(value,{'toolchain','metadata','declared_mismatch','public_api'},'cargo');toolchain=required_subset(section['toolchain'],{'toolchain','tools','cargo_public_api','targets','rustdoc_json_format','bootstrap'},'cargo_toolchain');public_api_tool=required_subset(toolchain['cargo_public_api'],{'version','binary_sha256','expected_binary_sha256_on_capture_host'},'cargo_public_api_tool');expected_binary='acdc7b1733d52476fc2ce456a2a0292b82c367566fe0d2ab15c12b99974c8d24'
	if toolchain['toolchain']!='1.96.0'or toolchain['targets']!=['aarch64-apple-darwin','x86_64-unknown-linux-gnu']or toolchain['rustdoc_json_format']!=57 or public_api_tool['version']!='cargo-public-api 0.52.0'or public_api_tool['binary_sha256']!=expected_binary or public_api_tool['expected_binary_sha256_on_capture_host']!=expected_binary or'RUSTC_BOOTSTRAP=1'not in canonical_json(toolchain['bootstrap']).decode('utf-8'):raise VerifyError('CARGO_TOOLCHAIN')
	tools=toolchain['tools']
	if not isinstance(tools,dict)or set(tools)!={'cargo','rustc','rustdoc'}:raise VerifyError('CARGO_TOOLS')
	tools_text=canonical_json(tools).decode('utf-8')
	if'1.96.0'not in tools_text or'ac68faa20'not in tools_text:raise VerifyError('CARGO_TOOL_IDENTITIES')
	metadata=require_fields(section['metadata'],{'capture_command','packages','workspace_members','feature_rows','counts','normalized_sha256'},'cargo_metadata');packages=metadata['packages']
	if not isinstance(packages,list)or len(packages)!=16:raise VerifyError('CARGO_PACKAGE_COUNT')
	package_names:list[str]=[];target_rows:list[dict[str,Any]]=[];workspace_manifest=tomllib.loads(freeze_blobs['Cargo.toml'].decode('utf-8'));workspace_members=sorted(workspace_manifest['workspace']['members']);expected_manifest_paths={f"{member}/Cargo.toml"for member in workspace_members}
	for package in packages:
		package=require_fields(package,{'name','version','id','manifest_path','authors','description','edition','rust_version','license','repository','publish','features','targets','dependencies'},'cargo_package')
		if not isinstance(package['name'],str)or not package['name']or package['name']in package_names or package['version']!='0.1.0-experimental'or package['id']!=f"{package["name"]}@{package["version"]}"or not valid_path(package['manifest_path'])or not isinstance(package['features'],dict)or not isinstance(package['targets'],list)or not isinstance(package['dependencies'],list):raise VerifyError('CARGO_PACKAGE')
		package_names.append(package['name'])
		if package['manifest_path']not in expected_manifest_paths:raise VerifyError('CARGO_MANIFEST_PARTITION')
		manifest_payload=freeze_blobs.get(package['manifest_path'])
		if manifest_payload is None:raise VerifyError('CARGO_MANIFEST_MISSING')
		manifest=tomllib.loads(manifest_payload.decode('utf-8'));package_table=manifest.get('package')
		if not isinstance(package_table,dict)or package_table.get('name')!=package['name']or package['features']!=manifest.get('features',{}):raise VerifyError('CARGO_MANIFEST_BINDING')
		for target in package['targets']:
			target=required_subset(target,{'name','kind','required_features','src_path'},'cargo_target')
			if not isinstance(target['name'],str)or not target['name']or not isinstance(target['kind'],list)or not target['kind']or not valid_path(target['src_path'])or not isinstance(target['required_features'],list)or target['src_path']not in freeze_blobs:raise VerifyError('CARGO_TARGET')
			target_rows.append({'package':package['name'],'name':target['name'],'kind':target['kind'],'required_features':target['required_features'],'src_path':target['src_path']})
	if package_names!=sorted(package_names)or len(target_rows)!=22 or{item['manifest_path']for item in packages}!=expected_manifest_paths or metadata['workspace_members']!=package_names:raise VerifyError('CARGO_PACKAGE_ORDER')
	feature_rows=metadata['feature_rows']
	if not isinstance(feature_rows,list)or len(feature_rows)!=8 or feature_rows!=sorted(feature_rows,key=lambda item:(item.get('package',''),item.get('feature',''))):raise VerifyError('CARGO_FEATURE_ROWS')
	package_features:dict[str,set[str]]={package:set()for package in EXPECTED_LIBRARY_PACKAGES}
	for row in feature_rows:
		row=require_fields(row,{'package','feature','members'},'cargo_feature')
		if row['package']not in package_names or not isinstance(row['feature'],str)or not row['feature']or not isinstance(row['members'],list):raise VerifyError('CARGO_FEATURE')
		if row['feature']!='default'and row['package']in package_features:package_features[row['package']].add(row['feature'])
	if sum(map(len,package_features.values()))!=5:raise VerifyError('CARGO_NAMED_FEATURE_COUNT')
	counts=metadata['counts']
	if counts!={'packages':16,'targets':22,'lib':15,'bin':2,'example':4,'test':1,'feature_rows':8}:raise VerifyError('CARGO_COUNTS')
	normalized_without_digest={key:item for(key,item)in metadata.items()if key!='normalized_sha256'};digest_matches(metadata['normalized_sha256'],normalized_without_digest,'cargo_metadata');mismatch=section['declared_mismatch']
	if not isinstance(mismatch,dict)or mismatch.get('observed')!={'version':'0.1.0-experimental','authors':['Sepahead'],'publish':False}or mismatch.get('release_target')!=RELEASE_TARGET or mismatch.get('expected_author')!=AUTHOR['name']or mismatch.get('is_release_metadata_aligned')is not False or not isinstance(mismatch.get('finding'),str)or not mismatch['finding']:raise VerifyError('CARGO_RELEASE_METADATA_MISMATCH')
	validate_rust_api(section['public_api'],package_features);target_rows.sort(key=lambda item:(item['package'],item['name'],item['kind']));return target_rows
def expected_python_cli_facts(entries:list[dict[str,Any]],blobs:dict[str,bytes])->list[dict[str,Any]]:
	result:list[dict[str,Any]]=[]
	for entry in entries:
		path=entry['path']
		if not path.startswith('tools/')or not path.endswith('.py'):continue
		payload=blobs[path]
		try:text=payload.decode('utf-8');syntax=ast.parse(text,filename=path)
		except(UnicodeDecodeError,SyntaxError)as error:raise VerifyError('PYTHON_CLI_SOURCE')from error
		has_main=False;parser_calls=0
		for node in ast.walk(syntax):
			if isinstance(node,ast.If)and isinstance(node.test,ast.Compare)and isinstance(node.test.left,ast.Name)and node.test.left.id=='__name__'and len(node.test.comparators)==1 and isinstance(node.test.comparators[0],ast.Constant)and node.test.comparators[0].value=='__main__':has_main=True
			if isinstance(node,ast.Call):
				function=node.func
				if isinstance(function,ast.Attribute)and function.attr=='ArgumentParser'or isinstance(function,ast.Name)and function.id=='ArgumentParser':parser_calls+=1
		executable=entry['git_mode']=='100755'and text.startswith('#!')
		if not has_main and not executable:continue
		result.append({'path':path,'sha256':sha256(payload),'entry_kind':'PYTHON','has_main_guard':has_main,'executable_shebang':executable,'parser':'ARGPARSE'if parser_calls else'SOURCE_DEFINED_OR_NO_ARGUMENT_PARSER','argument_parser_calls':parser_calls})
	return result
def validate_cli_inventory(value:Any,freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],cargo_targets:list[dict[str,Any]])->None:
	section=require_fields(value,{'cargo_targets','python_entry_points','shell_entry_points','just_recipes','runtime_observations','candidate_projection','counts'},'cli')
	if section['cargo_targets']!=cargo_targets:raise VerifyError('CLI_CARGO_TARGETS')
	python_entries=expected_python_cli_facts(freeze_entries,freeze_blobs)
	if section['python_entry_points']!=python_entries or len(python_entries)!=45 or sum(item['parser']=='ARGPARSE'for item in python_entries)!=16:raise VerifyError('CLI_PYTHON_ENTRIES')
	expected_shell=[]
	for entry in freeze_entries:
		path=entry['path']
		if not path.startswith('tools/')or not path.endswith('.sh'):continue
		payload=freeze_blobs[path]
		if not payload.startswith(b'#!'):raise VerifyError('CLI_SHELL_SHEBANG')
		expected_shell.append({'path':path,'sha256':sha256(payload),'entry_kind':'SHELL','executable':entry['git_mode']=='100755'})
	if section['shell_entry_points']!=expected_shell:raise VerifyError('CLI_SHELL_ENTRIES')
	recipes=section['just_recipes'];expected_recipes:list[str]=[]
	try:just_lines=freeze_blobs['justfile'].decode('utf-8').splitlines()
	except UnicodeDecodeError as error:raise VerifyError('CLI_JUST_UTF8')from error
	for line in just_lines:
		if not line or line[0].isspace()or line.startswith(('#','@','set ','export ')):continue
		match=re.match('([A-Za-z0-9][A-Za-z0-9_-]*)(?:\\s+[^:=]+)?\\s*:(?!=)',line)
		if match is not None:expected_recipes.append(match.group(1))
	expected_recipes=sorted(expected_recipes)
	if not isinstance(recipes,list)or recipes!=expected_recipes or recipes!=sorted(set(recipes))or not all(isinstance(item,str)and item for item in recipes):raise VerifyError('CLI_JUST_RECIPES')
	runtime=section['runtime_observations'];expected_codes={'gate_no_arguments':2,'gate_version':0,'gate_version_trailing_argument':0,'gate_check_config':0,'gate_check_config_trailing_argument':0,'gate_unknown_argument':2,'ctl_no_arguments':2,'ctl_argument':2};expected_argv={'gate_no_arguments':['haldir-gate'],'gate_version':['haldir-gate','--version'],'gate_version_trailing_argument':['haldir-gate','--version','ignored'],'gate_check_config':['haldir-gate','--check-config'],'gate_check_config_trailing_argument':['haldir-gate','--check-config','ignored'],'gate_unknown_argument':['haldir-gate','--unknown'],'ctl_no_arguments':['haldir-ctl'],'ctl_argument':['haldir-ctl','--version']}
	if not isinstance(runtime,list)or len(runtime)!=len(expected_codes):raise VerifyError('CLI_RUNTIME_COUNT')
	by_scenario:dict[str,dict[str,Any]]={}
	for item in runtime:
		item=require_fields(item,{'scenario','argv','exit_code','stdout','stderr','stdout_sha256','stderr_sha256'},'cli_runtime')
		if item['scenario']in by_scenario or item['scenario']not in expected_codes or item['exit_code']!=expected_codes[item['scenario']]or item['argv']!=expected_argv[item['scenario']]or not isinstance(item['argv'],list)or not item['argv']or not all(isinstance(argument,str)for argument in item['argv'])or not isinstance(item['stdout'],str)or not isinstance(item['stderr'],str)or not(item['stdout']or item['stderr'])or item['stdout_sha256']!=sha256(item['stdout'].encode('utf-8'))or item['stderr_sha256']!=sha256(item['stderr'].encode('utf-8')):raise VerifyError('CLI_RUNTIME')
		by_scenario[item['scenario']]=item
	if set(by_scenario)!=set(expected_codes):raise VerifyError('CLI_RUNTIME_PARTITION')
	if by_scenario['gate_version']['stdout']!=by_scenario['gate_version_trailing_argument']['stdout']or by_scenario['gate_version']['stderr']!=by_scenario['gate_version_trailing_argument']['stderr']:raise VerifyError('CLI_TRAILING_ARGUMENT_QUIRK')
	projection=section['candidate_projection']
	if not isinstance(projection,dict)or projection.get('candidate_files_are_not_in_freeze_counts')!=[PRODUCT_PATH,PRODUCT_TESTS_PATH]or not isinstance(projection.get('rule'),str)or not projection['rule']:raise VerifyError('CLI_CANDIDATE_PROJECTION')
	expected_counts={'cargo_targets':22,'python_entry_points':45,'python_argument_parser_entry_points':16,'shell_entry_points':len(expected_shell),'just_recipes':len(recipes),'runtime_observations':8}
	if section['counts']!=expected_counts:raise VerifyError('CLI_COUNTS')
def validate_documentation_inventory(value:Any,freeze_entries:list[dict[str,Any]])->None:
	section=require_fields(value,{'markdown_paths','baseline_text_paths','required_root_documents','other_documentation_surfaces','counts'},'documentation');paths=[item['path']for item in freeze_entries];markdown=sorted(path for path in paths if path.casefold().endswith('.md'));baseline=sorted(path for path in paths if path.casefold().endswith(('.md','.rst','.txt')))
	if section['markdown_paths']!=markdown or section['baseline_text_paths']!=baseline or len(markdown)!=48 or len(baseline)!=49:raise VerifyError('DOCUMENTATION_PATHS')
	expected_root=[{'path':'AGENTS.md','status':'MISSING_PLANNED_LATER_TASK'},{'path':'CHANGELOG.md','status':'MISSING_PLANNED_LATER_TASK'},{'path':'CLAUDE.md','status':'MISSING_PLANNED_LATER_TASK'},{'path':'CONTRIBUTING.md','status':'PRESENT'},{'path':'README.md','status':'PRESENT'},{'path':'SECURITY.md','status':'PRESENT'}]
	if section['required_root_documents']!=expected_root:raise VerifyError('DOCUMENTATION_ROOT_STATUS')
	surfaces=section['other_documentation_surfaces']
	if not isinstance(surfaces,dict)or set(surfaces)!={'rustdoc','cargo_package_descriptions','cli_help_and_errors','configuration_comments','github_description'}or not all(isinstance(item,str)and item for item in surfaces.values()):raise VerifyError('DOCUMENTATION_OTHER_SURFACES')
	if section['counts']!={'markdown':48,'baseline_md_rst_txt':49,'required_root_present':3,'required_root_missing':3}:raise VerifyError('DOCUMENTATION_COUNTS')
def validate_public_inventory_v2(value:Any,repo:Path,freeze_commit:str,freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],implementation_entries:list[dict[str,Any]],implementation_blobs:dict[str,bytes])->None:
	record=require_product_identity(value,'haldir.ch-t003.public-surface-inventory.v1',{'source','policy','records','archives','cargo','cli','ipc','schemas','documentation','candidate_implementation','counts','digests'},'public_inventory');source=require_fields(record['source'],{'freeze_commit','freeze_tree','object_format','signature','regular_blob_count','aggregate_blob_bytes','resource_limits'},'public_source');freeze_meta=commit_meta(repo,freeze_commit);allowed_signers=freeze_blobs['release/0.9.0/allowed-signers'];signature=required_subset(source['signature'],{'verified','allowed_signers_sha256','verification_transcript_sha256'},'public_source_signature')
	if source['freeze_commit']!=freeze_commit or source['freeze_tree']!=freeze_meta['tree']or source['object_format']!='sha1'or source['regular_blob_count']!=426 or source['aggregate_blob_bytes']!=sum(len(payload)for payload in freeze_blobs.values())or source['resource_limits']!={'per_blob_bytes':4194304,'aggregate_blob_bytes':67108864,'per_archive_member_bytes':4194304,'aggregate_archive_expanded_bytes':16777216,'per_output_bytes':4194304}or signature['verified']is not True or signature['allowed_signers_sha256']!=sha256(allowed_signers)or re.fullmatch('[0-9a-f]{64}',signature['verification_transcript_sha256'])is None:raise VerifyError('PUBLIC_SOURCE')
	if record['policy']!={'id':'HALDIR_PUBLIC_SURFACE_COMPLETE_F_TREE_POLICY_V1','scope':'ALL_REGULAR_GIT_BLOBS_AT_SIGNED_F_TREE','ordering':'UTF8_PATH_ASCENDING','classification_partition':['BUILD_OR_DEPLOYMENT','EXCLUDED_INTERNAL_EVIDENCE_OR_RELEASE','EXCLUDED_INTERNAL_TEST_OR_TOOL','EXCLUDED_NONINTERFACE_ASSET','PUBLIC_API_OR_SCHEMA','PUBLIC_DOCUMENTATION'],'public_classifications':['BUILD_OR_DEPLOYMENT','PUBLIC_API_OR_SCHEMA','PUBLIC_DOCUMENTATION'],'excluded_classifications':['EXCLUDED_INTERNAL_EVIDENCE_OR_RELEASE','EXCLUDED_INTERNAL_TEST_OR_TOOL','EXCLUDED_NONINTERFACE_ASSET'],'unknown_path_or_extension':'FAIL','nonregular_git_entry':'FAIL','lfs_pointer':'FAIL','structured_parse_error_or_duplicate_key':'FAIL','compiler_api_precedence':'PINNED_COMPILER_RESOLVED_ORACLE_OVERRIDES_LEXICAL_PUB_HEURISTICS'}:raise VerifyError('PUBLIC_POLICY')
	validate_inventory_file_records(record['records'],freeze_entries,freeze_blobs);validate_archive_products(record['archives'],freeze_entries,freeze_blobs);cargo_targets=validate_cargo_inventory(record['cargo'],freeze_blobs);validate_cli_inventory(record['cli'],freeze_entries,freeze_blobs,cargo_targets);validate_ipc(record['ipc'],freeze_blobs);validate_schemas(record['schemas'],freeze_blobs);validate_documentation_inventory(record['documentation'],freeze_entries);validate_candidate_plan(record['candidate_implementation'],implementation_entries,implementation_blobs);counts=record['counts'];classifications:dict[str,int]={}
	for item in record['records']:classifications[item['classification']]=classifications.get(item['classification'],0)+1
	archives=record['archives'];expected_counts={'regular_blobs':426,'aggregate_blob_bytes':sum(len(payload)for payload in freeze_blobs.values()),'surface_records':sum(item['disposition']=='SURFACE'for item in record['records']),'excluded_records':sum(item['disposition']=='EXCLUDED'for item in record['records']),'by_classification':dict(sorted(classifications.items())),'zip_archives':4,'gzip_archives':30,'archive_members':sum(item['member_count']for item in archives),'archive_expanded_bytes':sum(item['expanded_bytes']for item in archives),'candidate_paths':9,'expected_implementation_regular_blobs':434}
	if counts!=expected_counts:raise VerifyError('PUBLIC_COUNTS')
	digests=record['digests'];expected_digests={'records_sha256':sha256(canonical_json(record['records'])),'archives_sha256':sha256(canonical_json(record['archives'])),'cargo_sha256':sha256(canonical_json(record['cargo'])),'cli_sha256':sha256(canonical_json(record['cli'])),'ipc_sha256':sha256(canonical_json(record['ipc'])),'schemas_sha256':sha256(canonical_json(record['schemas'])),'documentation_sha256':sha256(canonical_json(record['documentation'])),'candidate_implementation_sha256':sha256(canonical_json(record['candidate_implementation']))}
	if digests!=expected_digests:raise VerifyError('PUBLIC_DIGESTS')
def validate_products(repo:Path,freeze_commit:str,implementation_commit:str)->None:
	implementation_entries,implementation_blobs=tree_snapshot(repo,implementation_commit);freeze_entries,freeze_blobs=tree_snapshot(repo,freeze_commit)
	if len(freeze_entries)!=426 or len(implementation_entries)!=434:raise VerifyError('PRODUCT_TREE_COUNTS')
	products={path:load_json(implementation_blobs[path])for path in(PUBLIC_INVENTORY_PATH,CLAIM_TIER_PATH,REVIEW_OVERLAY_PATH,LEDGER_COMPOSITION_PATH,GITHUB_METADATA_PATH,CLAIM_LANGUAGE_PATH)};validate_public_inventory_v2(products[PUBLIC_INVENTORY_PATH],repo,freeze_commit,freeze_entries,freeze_blobs,implementation_entries,implementation_blobs);claim_state=load_json(freeze_blobs[CLAIMS_STATE_PATH],canonical=False)
	if not isinstance(claim_state,dict):raise VerifyError('CLAIM_STATE_SHAPE')
	validate_claim_tier_product(products[CLAIM_TIER_PATH],freeze_commit,commit_meta(repo,freeze_commit)['tree'],freeze_blobs[CLAIM_LEDGER_PATH],implementation_blobs[CLAIM_LEDGER_PATH],freeze_blobs[CLAIMS_STATE_PATH],claim_state);validate_claim_language_product(products[CLAIM_LANGUAGE_PATH],freeze_entries,freeze_blobs,implementation_blobs[CLAIM_LEDGER_PATH],products[PUBLIC_INVENTORY_PATH],products[GITHUB_METADATA_PATH]);validate_review_overlay(products[REVIEW_OVERLAY_PATH],repo,freeze_commit,freeze_entries,freeze_blobs,implementation_entries,implementation_blobs);validate_ledger_composition_v2(products[LEDGER_COMPOSITION_PATH],repo,freeze_commit,freeze_entries,freeze_blobs,implementation_commit,implementation_entries,implementation_blobs);validate_github_metadata_v2(products[GITHUB_METADATA_PATH],freeze_commit,commit_time(repo,freeze_commit),commit_time(repo,implementation_commit))
EVIDENCE_COMMON_FIELDS={'schema_id','evidence_id','task_id','epoch','freeze_commit','implementation_commit','started_at_utc','completed_at_utc','result'}
EVIDENCE_SPECIFIC_FIELDS={'CH-T003-E01':{'implementation_plan','requirement_ids','test_ids','evidence_ids','review_ids','snapshot','composition','counts','digests'},'CH-T003-E02':{'commands','environment'},'CH-T003-E03':{'accepted_vectors','rejected_vectors','accepted_counterfactuals','rejected_counterfactuals','command_ids'},'CH-T003-E04':{'techniques','covered_requirement_ids','covered_counterfactual_ids','covered_test_ids'},'CH-T003-E05':{'declared_maxima','observed_maxima','observed_distributions','command_ids','capacity_disposition'},'CH-T003-E06':{'baseline_commit','prior_lifecycle','freeze_tree','implementation_tree','registered_files','implementation_files','prior_artifacts','tree_snapshot','lifecycle_diffs','tool_identities','digests'},'CH-T003-E07':{'claim_outcome','implementation_paths','claim_transition','runtime_surface_changed','release_authority','publication_authority','requirements_complete'},'CH-T003-E08':{'snapshot','composition','assignments','completion_records','counts','digests','review_boundary'},'CH-T003-E09':{'source_file','policy','counts','digests','section_results','limitations'},'CH-T003-E10':{'source_file','claim_ledger','prior_active_claims','counts','digests','tier_vocabulary','transition','release_boundary'},'CH-T003-E11':{'source_file','capture_window','capture_policy','endpoints','normalized','digests','redaction_boundary'},'CH-T003-E12':{'repository','head_ref','commit','workflow_definitions','workflow_runs','workflow_attempts','workflow_jobs','captures','capture_policy','digests'},'CH-T003-E13':{'source_file','toolchain','lockfile','targets','profiles','commands','api_sets','source_cross_checks','digests','limitations'}}
COMMAND_FIELDS={'id','phase','argv','cwd','exit_code','started_at_utc','completed_at_utc','stdout','stdout_sha256','stderr','stderr_sha256'}
REVIEW_BOUNDARY={'automated_review_only':True,'independent_automated_review_performed':True,'independent_human_review_performed':False,'named_human_review_performed':False,'required_external_human_review_satisfied':None}
QUALIFICATION_FIELDS={'author','effective_on','epoch','evidence_records','freeze_commit','human_review_boundary','implementation_commit','limitations','persistent_identifier','registered_files','release_authority','release_target','review_finding_dispositions','review_records','schema_version','selected_claim_outcome_id','task_id','twenty_lens_reviews'}
EVIDENCE_RECORD_FIELDS={'completed_at_utc','file','id','kind','result','started_at_utc','subject_commits'}
REVIEW_RECORD_FIELDS={'id','kind','file','reviewer','independent_from_release_author','external','human','named_human_reviewer','release_approver','reproduced_decisive_evidence','reviewed_all_changed_lines_and_context','detached_signature','decision','started_at_utc','completed_at_utc'}
REVIEW_REPORT_FIELDS={'schema_version','task_id','epoch','requirement','reviewer','freeze_commit','implementation_commit','implementation_diff','all_changed_lines_reviewed','reviewed_relevant_context','relevant_unchanged_context_reviewed','decisive_reproduction','reviewer_provenance','findings','limitations','decision'}
TECHNIQUE_KINDS='BOUNDARY','METAMORPHIC','DIFFERENTIAL','MUTATION','HOSTILE_ARCHIVE','PROPERTY','DETERMINISTIC_SEEDED_FUZZ'
SECTION_IDS='TREE_CLASSIFICATION','RUST_SOURCE','COMPILER_OUTPUT','CARGO_PACKAGES_TARGETS_FEATURES','CLI','IPC','SCHEMAS','DOCUMENTATION','ARCHIVES','CONFIGURATION','BUILD','DEPLOYMENT','RELEASE_STATE'
EXPECTED_WORKFLOW_JOBS={'.github/workflows/ci.yml':{'build-test','clean-build','feature-matrix','interop','macos-compile','supply-chain'},'.github/workflows/formal.yml':{'tlc-model-check'}}
EXPORTED_MACROS='__hc_build','__hc_count','__hc_encode','__hc_field_ty','__hc_raw_ty','canonical_struct','tagged_enum'
PRIVATE_CONSTANTS='HARD_MAX_INTENT_QUEUE','HARD_MAX_ZENOH_MESSAGE_BYTES','HARD_MAX_ZENOH_RX_BUFFER_BYTES'
ACTIVATION_FIELDS={'schema_version','task_id','epoch','release_target','author','persistent_identifier','effective_on','freeze_commit','implementation_commit','qualification_commit','qualification_record','verifier_receipt','activation_evidence_records','requirements_record','active_claims_record','selected_claim_outcome','decision'}
ACTIVATION_EVIDENCE_RECORD_FIELDS={'completed_at_utc','file','id','kind','result','started_at_utc','subject_commit'}
CI_JOB_NAMES='build-test','clean-build','feature-matrix','interop','macos-compile','supply-chain'
FORMAL_JOB_NAMES='tlc-model-check',
HOSTED_WORKFLOW_SPECS=('.github/workflows/ci.yml',CI_JOB_NAMES),('.github/workflows/formal.yml',FORMAL_JOB_NAMES)
ALL_HOSTED_JOB_NAMES=*CI_JOB_NAMES,*FORMAL_JOB_NAMES
JOB_LOG_MEMBERS={name:f"{index}_{name}.txt"for(index,name)in enumerate(ALL_HOSTED_JOB_NAMES)}
_TREE_SNAPSHOT_CACHE:dict[tuple[str,str],tuple[list[dict[str,Any]],dict[str,bytes]]]={}
REVIEW_PHASES={'CH-T003-R01':('PRODUCT_TESTS','REGISTERED_TESTS','EXACT_IMPLEMENTATION_VERIFY'),'CH-T003-R02':('PRODUCT_VERIFY','NEGATIVE_TESTS','EXACT_IMPLEMENTATION_VERIFY'),'CH-T003-R03':('PRODUCT_VERIFY','TECHNIQUE_TESTS','EXACT_IMPLEMENTATION_VERIFY'),'CH-T003-R04':('PRODUCT_VERIFY','REGISTERED_TESTS','EXACT_IMPLEMENTATION_VERIFY')}
def validate_retained_command(value:Any,*,window_start:datetime,window_end:datetime,expected_phase:str|None=None,expected_argv:list[str]|None=None,maximum_stream_bytes:int=65536)->tuple[datetime,datetime]:
	if type(maximum_stream_bytes)is not int or not 1<=maximum_stream_bytes<=4194304:raise VerifyError('RETAINED_COMMAND_BOUND')
	command_record=require_fields(value,COMMAND_FIELDS,'retained_command');started=parse_utc(command_record['started_at_utc']);completed=parse_utc(command_record['completed_at_utc']);stdout=command_record['stdout'];stderr=command_record['stderr']
	if not window_start<=started<=completed<=window_end or not isinstance(command_record['id'],str)or not command_record['id']or not isinstance(command_record['phase'],str)or not command_record['phase']or expected_phase is not None and command_record['phase']!=expected_phase or not isinstance(command_record['argv'],list)or not command_record['argv']or not all(isinstance(argument,str)and argument and len(argument.encode('utf-8'))<=4096 for argument in command_record['argv'])or expected_argv is not None and command_record['argv']!=expected_argv or command_record['cwd']!='.'or command_record['exit_code']!=0 or not isinstance(stdout,str)or not isinstance(stderr,str)or len(stdout.encode('utf-8'))>maximum_stream_bytes or len(stderr.encode('utf-8'))>maximum_stream_bytes or not(stdout or stderr)or command_record['stdout_sha256']!=sha256(stdout.encode('utf-8'))or command_record['stderr_sha256']!=sha256(stderr.encode('utf-8')):raise VerifyError('RETAINED_COMMAND')
	return started,completed
def require_string_list(value:Any,label:str,*,nonempty:bool=False,unique:bool=False,sorted_utf8:bool=False)->list[str]:
	if not isinstance(value,list)or nonempty and not value or not all(isinstance(item,str)and item for item in value)or unique and len(value)!=len(set(value))or sorted_utf8 and value!=sorted(value,key=lambda item:item.encode('utf-8')):raise VerifyError(f"STRING_LIST:{label}")
	return value
def freeze_control_sets(freeze:dict[str,Any])->tuple[list[str],list[str],list[str],list[str]]:
	controls=freeze.get('normative_controls');counterfactuals=freeze.get('mandatory_counterfactuals')
	if not isinstance(controls,list)or not isinstance(counterfactuals,list):raise VerifyError('FREEZE_CONTROL_SETS')
	requirement_ids:list[str]=[];counterfactual_ids:list[str]=[];test_ids:list[str]=[]
	for(expected_index,item)in enumerate(controls,1):
		item=require_fields(item,{'id','statement','accepted_test_id','rejected_test_id'},'freeze_control')
		if item['id']!=f"CH-T003-N{expected_index:02d}"or not isinstance(item['statement'],str)or not item['statement']:raise VerifyError('FREEZE_CONTROL')
		requirement_ids.append(item['id']);test_ids.extend((item['accepted_test_id'],item['rejected_test_id']))
	for(expected_index,item)in enumerate(counterfactuals,1):
		item=require_fields(item,{'id','statement','accepted_test_id','rejected_test_id'},'freeze_counterfactual')
		if item['id']!=f"CH-T003-CF{expected_index:02d}"or not isinstance(item['statement'],str)or not item['statement']:raise VerifyError('FREEZE_COUNTERFACTUAL')
		counterfactual_ids.append(item['id']);test_ids.extend((item['accepted_test_id'],item['rejected_test_id']))
	if len(requirement_ids)!=20 or len(counterfactual_ids)!=10 or len(test_ids)!=len(set(test_ids)):raise VerifyError('FREEZE_CONTROL_COUNTS')
	return requirement_ids,counterfactual_ids,sorted(test_ids,key=lambda item:item.encode('utf-8')),test_ids
def composition_projection(value:Any)->dict[str,Any]:
	if not isinstance(value,dict):raise VerifyError('COMPOSITION_PROJECTION')
	coverage=value.get('coverage')
	if not isinstance(coverage,dict):raise VerifyError('COMPOSITION_PROJECTION')
	return{'source_file':LEDGER_COMPOSITION_PATH,'freeze_partition_sha256':sha256(canonical_json(coverage.get('freeze_partition'))),'candidate_partition_sha256':sha256(canonical_json(coverage.get('candidate_partition'))),'review_overlay_sha256':sha256(canonical_json(coverage.get('review_overlay'))),'sibling_products_sha256':sha256(canonical_json(coverage.get('sibling_products')))}
def evidence_section_results(public:dict[str,Any])->list[dict[str,Any]]:records=public['records'];cargo=public['cargo'];mapping:dict[str,Any]={'TREE_CLASSIFICATION':records,'RUST_SOURCE':[item for item in records if item['path'].endswith('.rs')],'COMPILER_OUTPUT':cargo['public_api'],'CARGO_PACKAGES_TARGETS_FEATURES':cargo,'CLI':public['cli'],'IPC':public['ipc'],'SCHEMAS':public['schemas'],'DOCUMENTATION':public['documentation'],'ARCHIVES':public['archives'],'CONFIGURATION':[item for item in records if'CONFIGURATION'in item['surface_types']],'BUILD':[item for item in records if'BUILD'in item['surface_types']],'DEPLOYMENT':[item for item in records if'DEPLOYMENT'in item['surface_types']],'RELEASE_STATE':{'candidate_implementation':public['candidate_implementation'],'release_target':public['release_target'],'persistent_identifier':public['persistent_identifier']}};return[{'id':identifier,'result':'PASS','record_count':len(mapping[identifier])if isinstance(mapping[identifier],(list,dict))else 1,'digest':sha256(canonical_json(mapping[identifier]))}for identifier in SECTION_IDS]
def reviewer_registry(freeze:dict[str,Any])->dict[str,dict[str,Any]]:
	records=freeze.get('reviewer_registry')
	if not isinstance(records,list)or len(records)!=len(REVIEW_SPECS):raise VerifyError('REVIEWER_REGISTRY')
	result:dict[str,dict[str,Any]]={};principals:set[str]=set();keys:set[str]=set();fingerprints:set[str]=set()
	for(index,item)in enumerate(records,1):
		item=require_fields(item,{'requirement_id','kind','path','reviewer','public_key','key_fingerprint','trust_basis'},'reviewer_registry_item');identifier=item['requirement_id'];expected_identifier,expected_kind,_expected_name=REVIEW_SPECS[index-1]
		if identifier in result or identifier not in REVIEW_PATHS or identifier!=expected_identifier:raise VerifyError('REVIEWER_REGISTRY_ID')
		reviewer=require_fields(item['reviewer'],{'name','principal','classification','organization'},'reviewer_identity');expected_reviewer={'name':f"CH-T003 Independent Automated Reviewer Lane {index:02d}",'principal':f"ch-t003-e0001-lane-{index:02d}@local.invalid",'classification':'INDEPENDENT_AUTOMATED','organization':'Independent Automated Technical Review'}if index<4 else{'name':'CH-T003 Automated Lead Support','principal':'ch-t003-e0001-automated-lead-support@local.invalid','classification':'AUTOMATED_LEAD_SUPPORT','organization':'Automated Technical Review'};public_key=item['public_key'];fingerprint=item['key_fingerprint']
		if item['kind']!=expected_kind or item['path']!=REVIEW_PATHS[identifier]or reviewer!=expected_reviewer or reviewer['name']==AUTHOR['name']or reviewer['principal']==AUTHOR['email']or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@+-]{0,254}',reviewer['principal'])is None or not isinstance(public_key,str)or len(public_key)>1024 or re.fullmatch('ssh-ed25519 [A-Za-z0-9+/]+={0,2}',public_key)is None or not isinstance(fingerprint,str)or re.fullmatch('SHA256:[A-Za-z0-9+/]{43}',fingerprint)is None or public_key_fingerprint(public_key)!=fingerprint or item['trust_basis']!='SOURCE_SIGNER_ASSERTED_KEY_FROZEN_IN_SIGNED_F':raise VerifyError('REVIEWER_REGISTRY_BINDING')
		principals.add(reviewer['principal']);keys.add(public_key);fingerprints.add(fingerprint);result[identifier]=item
	if list(result)!=[item[0]for item in REVIEW_SPECS]:raise VerifyError('REVIEWER_REGISTRY_ORDER')
	if not(len(principals)==len(records)and len(keys)==len(records)and len(fingerprints)==len(records)):raise VerifyError('REVIEWER_REGISTRY_SEPARATION')
	return result
def public_key_fingerprint(public_key:str)->str:
	fields=public_key.split(' ')
	if len(fields)!=2 or fields[0]!='ssh-ed25519':raise VerifyError('PUBLIC_KEY')
	try:decoded=base64.b64decode(fields[1],validate=True)
	except(binascii.Error,ValueError)as error:raise VerifyError('PUBLIC_KEY')from error
	algorithm=b'ssh-ed25519'
	if len(decoded)!=4+len(algorithm)+4+32:raise VerifyError('PUBLIC_KEY')
	algorithm_size=int.from_bytes(decoded[:4],'big');algorithm_end=4+algorithm_size
	if algorithm_size!=len(algorithm)or decoded[4:algorithm_end]!=algorithm:raise VerifyError('PUBLIC_KEY')
	key_size=int.from_bytes(decoded[algorithm_end:algorithm_end+4],'big');key_start=algorithm_end+4
	if key_size!=32 or key_start+key_size!=len(decoded):raise VerifyError('PUBLIC_KEY')
	return'SHA256:'+base64.b64encode(hashlib.sha256(decoded).digest()).decode('ascii').rstrip('=')
def review_attestation_payload(record:dict[str,Any],freeze_commit:str,implementation_commit:str)->bytes:unsigned={key:copy.deepcopy(value)for(key,value)in record.items()if key!='detached_signature'};return canonical_json({'schema_version':'1.0.0','purpose':'SUCCESSOR_IMPLEMENTATION_QUALIFICATION_REVIEW','task_id':TASK_ID,'epoch':EPOCH,'freeze_commit':freeze_commit,'implementation_commit':implementation_commit,'review_record':unsigned})
def verify_review_signature(registry_item:dict[str,Any],namespace:str,signature:str,payload:bytes)->None:
	reviewer=registry_item['reviewer']
	if not isinstance(signature,str)or len(signature.encode('ascii','strict'))>8192 or not signature.startswith('-----BEGIN SSH SIGNATURE-----\n')or not signature.endswith('-----END SSH SIGNATURE-----\n'):raise VerifyError('REVIEW_SIGNATURE_ARMOR')
	with tempfile.TemporaryDirectory(prefix='haldir-ch-t003-review-verify-')as directory:
		root=Path(directory);allowed=root/'allowed-signers';signature_path=root/'review.sig';allowed.write_text(f"{reviewer["principal"]} {registry_item["public_key"]}\n",encoding='ascii');signature_path.write_text(signature,encoding='ascii')
		try:completed=subprocess.run(['/usr/bin/ssh-keygen','-Y','verify','-f',os.fspath(allowed),'-I',reviewer['principal'],'-n',namespace,'-s',os.fspath(signature_path)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False,timeout=30,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'})
		except(OSError,subprocess.TimeoutExpired)as error:raise VerifyError('REVIEW_SIGNATURE_TOOL')from error
	if completed.returncode!=0 or len(completed.stdout)>65536 or len(completed.stderr)>65536:raise VerifyError('REVIEW_SIGNATURE_INVALID')
def validate_common_evidence(value:Any,*,identifier:str,schema_id:str,freeze_commit:str,implementation_commit:str,implementation_time:datetime,qualification_time:datetime)->tuple[dict[str,Any],datetime,datetime]:
	record=require_fields(value,EVIDENCE_COMMON_FIELDS|EVIDENCE_SPECIFIC_FIELDS[identifier],f"evidence_{identifier}");started=parse_utc(record['started_at_utc']);completed=parse_utc(record['completed_at_utc'])
	if record['schema_id']!=schema_id or record['evidence_id']!=identifier or record['task_id']!=TASK_ID or record['epoch']!=EPOCH or record['freeze_commit']!=freeze_commit or record['implementation_commit']!=implementation_commit or record['result']!='PASS'or not implementation_time<=started<=completed<=qualification_time:raise VerifyError(f"EVIDENCE_IDENTITY:{identifier}")
	return record,started,completed
def validate_hosted_implementation_capture(value:dict[str,Any],*,implementation_commit:str,implementation_entries:list[dict[str,Any]],implementation_blobs:dict[str,bytes])->None:
	if value['repository']!={'owner':'sepahead','name':'haldir','full_name':'sepahead/haldir','api_url':'https://api.github.com/repos/sepahead/haldir'}or value['head_ref']!='refs/heads/main'or value['commit']!=implementation_commit:raise VerifyError('E12_REPOSITORY')
	definitions=value['workflow_definitions']
	if not isinstance(definitions,list)or[item.get('hosted_path')if isinstance(item,dict)else None for item in definitions]!=sorted(EXPECTED_WORKFLOW_JOBS):raise VerifyError('E12_WORKFLOW_DEFINITIONS')
	for item in definitions:
		item=require_fields(item,{'file','hosted_id','hosted_name','hosted_path','state'},'e12_workflow_definition');path=item['hosted_path']
		if item['file']!=exact_file_record(path,implementation_entries,implementation_blobs)or type(item['hosted_id'])is not int or not isinstance(item['hosted_name'],str)or not item['hosted_name']or item['state']!='active':raise VerifyError('E12_WORKFLOW_DEFINITION')
	runs=value['workflow_runs'];attempts=value['workflow_attempts'];jobs=value['workflow_jobs'];expected_run_fields={'id','name','path','event','status','conclusion','head_branch','head_sha','run_attempt','created_at','updated_at','html_url'}
	if not isinstance(runs,list)or len(runs)!=2 or not isinstance(attempts,list)or len(attempts)!=2 or[item.get('path')for item in runs]!=sorted(EXPECTED_WORKFLOW_JOBS)or[item.get('path')for item in attempts]!=sorted(EXPECTED_WORKFLOW_JOBS):raise VerifyError('E12_RUN_SET')
	for record in[*runs,*attempts]:
		record=require_fields(record,expected_run_fields,'e12_run')
		if record['path']not in EXPECTED_WORKFLOW_JOBS or type(record['id'])is not int or type(record['run_attempt'])is not int or record['event']!='push'or record['status']!='completed'or record['conclusion']!='success'or record['head_branch']!='main'or record['head_sha']!=implementation_commit or not isinstance(record['html_url'],str)or not record['html_url'].startswith('https://github.com/sepahead/haldir/actions/runs/'):raise VerifyError('E12_RUN_BINDING')
		parse_utc(record['created_at']);parse_utc(record['updated_at'])
	run_by_id={item['id']:item for item in attempts}
	if not isinstance(jobs,list)or len(jobs)!=7 or[item.get('name')for item in jobs]!=['tlc-model-check','build-test','clean-build','feature-matrix','interop','macos-compile','supply-chain']:
		if not isinstance(jobs,list)or len(jobs)!=7:raise VerifyError('E12_JOB_SET')
	observed_jobs:dict[str,set[str]]={path:set()for path in EXPECTED_WORKFLOW_JOBS};job_fields={'run_id','run_attempt','id','name','status','conclusion','started_at','completed_at','labels','steps'}
	for job in jobs:
		job=require_fields(job,job_fields,'e12_job');run=run_by_id.get(job['run_id'])
		if run is None or job['run_attempt']!=run['run_attempt']or type(job['id'])is not int or not isinstance(job['name'],str)or job['name']in observed_jobs[run['path']]or job['status']!='completed'or job['conclusion']!='success'or not isinstance(job['labels'],list)or not isinstance(job['steps'],list):raise VerifyError('E12_JOB_BINDING')
		parse_utc(job['started_at']);parse_utc(job['completed_at']);observed_jobs[run['path']].add(job['name'])
	if observed_jobs!=EXPECTED_WORKFLOW_JOBS:raise VerifyError('E12_JOB_NAMES')
	captures=value['captures']
	if not isinstance(captures,list)or len(captures)<7 or len(captures)>100 or[item.get('id')for item in captures]!=[f"CH-T003-GH{index:03d}"for index in range(1,len(captures)+1)]:raise VerifyError('E12_CAPTURES')
	capture_fields={'id','endpoint','http_status','etag','link','bytes','sha256','document'};total_capture_bytes=0
	for capture in captures:
		capture=require_fields(capture,capture_fields,'e12_capture');total_capture_bytes+=capture['bytes']
		if capture['http_status']!=200 or not isinstance(capture['endpoint'],str)or not capture['endpoint'].startswith('/repos/sepahead/haldir/')or capture['etag']is not None and not isinstance(capture['etag'],str)or capture['link']is not None and not isinstance(capture['link'],str)or type(capture['bytes'])is not int or not 0<=capture['bytes']<=1048576 or re.fullmatch('[0-9a-f]{64}',capture['sha256'])is None:raise VerifyError('E12_CAPTURE_BINDING')
	if total_capture_bytes>8388608:raise VerifyError('E12_CAPTURE_AGGREGATE')
	head_documents:list[Any]=[];workflow_documents:list[Any]=[];run_documents:list[Any]=[];attempt_documents:list[Any]=[];job_documents:list[Any]=[]
	for capture in captures:
		endpoint=capture['endpoint'];document=capture['document']
		if endpoint=='/repos/sepahead/haldir/commits/main':head_documents.append(document)
		elif endpoint.startswith('/repos/sepahead/haldir/actions/workflows?'):workflow_documents.append(document)
		elif endpoint.startswith('/repos/sepahead/haldir/actions/runs?'):run_documents.append(document)
		elif re.fullmatch('/repos/sepahead/haldir/actions/runs/\\d+/attempts/\\d+',endpoint):attempt_documents.append(document)
		elif re.fullmatch('/repos/sepahead/haldir/actions/runs/\\d+/attempts/\\d+/jobs\\?.+',endpoint):job_documents.append(document)
		else:raise VerifyError('E12_CAPTURE_ENDPOINT')
	if len(head_documents)!=1 or not isinstance(head_documents[0],dict)or head_documents[0].get('sha')!=implementation_commit or not workflow_documents or not run_documents or len(attempt_documents)!=2 or len(job_documents)<2:raise VerifyError('E12_CAPTURE_CLOSURE')
	raw_workflows:list[Any]=[]
	for document in workflow_documents:
		if not isinstance(document,dict)or not isinstance(document.get('workflows'),list):raise VerifyError('E12_RAW_WORKFLOWS')
		raw_workflows.extend(document['workflows'])
	workflow_by_path={item.get('path'):item for item in raw_workflows if isinstance(item,dict)and item.get('path')in EXPECTED_WORKFLOW_JOBS}
	if len(workflow_by_path)!=2:raise VerifyError('E12_RAW_WORKFLOW_SET')
	for definition in definitions:
		raw=workflow_by_path[definition['hosted_path']]
		if definition['hosted_id']!=raw.get('id')or definition['hosted_name']!=raw.get('name')or definition['state']!=raw.get('state'):raise VerifyError('E12_RAW_WORKFLOW_BINDING')
	raw_runs:list[Any]=[]
	for document in run_documents:
		if not isinstance(document,dict)or not isinstance(document.get('workflow_runs'),list):raise VerifyError('E12_RAW_RUNS')
		raw_runs.extend(document['workflow_runs'])
	raw_run_by_id={item.get('id'):item for item in raw_runs if isinstance(item,dict)};run_projection_fields='id','name','path','event','status','conclusion','head_branch','head_sha','run_attempt','created_at','updated_at','html_url'
	for run in runs:
		raw=raw_run_by_id.get(run['id'])
		if raw is None or run!={field:raw.get(field)for field in run_projection_fields}:raise VerifyError('E12_RAW_RUN_BINDING')
	raw_attempt_by_id={item.get('id'):item for item in attempt_documents if isinstance(item,dict)}
	for attempt in attempts:
		raw=raw_attempt_by_id.get(attempt['id'])
		if raw is None or attempt!={field:raw.get(field)for field in run_projection_fields}:raise VerifyError('E12_RAW_ATTEMPT_BINDING')
	raw_jobs:list[Any]=[]
	for document in job_documents:
		if not isinstance(document,dict)or not isinstance(document.get('jobs'),list):raise VerifyError('E12_RAW_JOBS')
		raw_jobs.extend(document['jobs'])
	raw_job_by_id={item.get('id'):item for item in raw_jobs if isinstance(item,dict)}
	for job in jobs:
		raw=raw_job_by_id.get(job['id'])
		if raw is None or job!={'run_id':raw.get('run_id'),'run_attempt':raw.get('run_attempt'),'id':raw.get('id'),'name':raw.get('name'),'status':raw.get('status'),'conclusion':raw.get('conclusion'),'started_at':raw.get('started_at'),'completed_at':raw.get('completed_at'),'labels':raw.get('labels'),'steps':raw.get('steps')}:raise VerifyError('E12_RAW_JOB_BINDING')
	policy=value['capture_policy']
	if policy!={'accept':'application/vnd.github+json','api_version':'2022-11-28','authorization_retained':False,'body_bound_bytes':1048576,'pagination':'FOLLOW_SAME_ORIGIN_NEXT_TO_CLOSURE','required_event':'push','required_head_branch':'main','required_head_sha':implementation_commit,'required_result':'completed/success'}:raise VerifyError('E12_CAPTURE_POLICY')
	if value['digests']!={'workflow_definitions_sha256':sha256(canonical_json(definitions)),'workflow_runs_sha256':sha256(canonical_json(runs)),'workflow_attempts_sha256':sha256(canonical_json(attempts)),'workflow_jobs_sha256':sha256(canonical_json(jobs)),'captures_sha256':sha256(canonical_json(captures))}:raise VerifyError('E12_DIGESTS')
def qualification_content_kind(path:str,payload:bytes)->str:
	lowered=path.casefold()
	for(suffix,kind)in(('.json','JSON'),('.py','PYTHON'),('.rs','RUST'),('.md','MARKDOWN'),('.toml','TOML'),('.yml','YAML'),('.yaml','YAML'),('.zip','ZIP'),('.gz','GZIP'),('.tgz','GZIP')):
		if lowered.endswith(suffix):return kind
	try:payload.decode('utf-8','strict')
	except UnicodeError:return'BINARY'
	return'TEXT_UTF8'
def assignment_evidence_ids(path:str)->list[str]:
	identifiers={'CH-T003-E01','CH-T003-E06','CH-T003-E08','CH-T003-E09'}
	if path in{CLAIM_LEDGER_PATH,CLAIM_TIER_PATH,CLAIM_LANGUAGE_PATH}:identifiers.add('CH-T003-E10')
	if path==GITHUB_METADATA_PATH or path.startswith('.github/'):identifiers.update({'CH-T003-E11','CH-T003-E12'})
	if path.endswith('.rs')or path in{'Cargo.toml','Cargo.lock','rust-toolchain.toml'}:identifiers.add('CH-T003-E13')
	return sorted(identifiers,key=lambda item:item.encode('utf-8'))
def assigned_review_lanes(path:str)->tuple[str,str]:lane=hashlib.sha256(path.encode('utf-8')).digest()[0]%3;return f"CH-T003-R{lane+1:02d}",f"CH-T003-R{(lane+1)%3+1:02d}"
def validate_qualification_evidence(*,repo:Path,freeze_commit:str,implementation_commit:str,qualification_commit:str,freeze:dict[str,Any],qualification:dict[str,Any],freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],implementation_entries:list[dict[str,Any]],implementation_blobs:dict[str,bytes],qualification_entries:list[dict[str,Any]],qualification_blobs:dict[str,bytes])->dict[str,dict[str,Any]]:
	implementation_time=commit_time(repo,implementation_commit);qualification_time=commit_time(repo,qualification_commit);products={path:load_json(implementation_blobs[path])for path in(PUBLIC_INVENTORY_PATH,CLAIM_TIER_PATH,REVIEW_OVERLAY_PATH,LEDGER_COMPOSITION_PATH,GITHUB_METADATA_PATH,CLAIM_LANGUAGE_PATH)};public=products[PUBLIC_INVENTORY_PATH];tier=products[CLAIM_TIER_PATH];composition=products[LEDGER_COMPOSITION_PATH];github=products[GITHUB_METADATA_PATH];evidence:dict[str,dict[str,Any]]={};intervals:dict[str,tuple[datetime,datetime]]={}
	for(identifier,_kind,_name,schema_id)in EVIDENCE_SPECS:
		path=EVIDENCE_PATHS[identifier]
		if len(qualification_blobs[path])>MAX_JSON_BYTES:raise VerifyError(f"EVIDENCE_SIZE:{identifier}")
		value=load_json(qualification_blobs[path]);record,started,completed=validate_common_evidence(value,identifier=identifier,schema_id=schema_id,freeze_commit=freeze_commit,implementation_commit=implementation_commit,implementation_time=implementation_time,qualification_time=qualification_time);evidence[identifier]=record;intervals[identifier]=started,completed
	common_starts={item['started_at_utc']for item in evidence.values()};common_completions={item['completed_at_utc']for item in evidence.values()}
	if len(common_starts)!=1 or len(common_completions)!=1:raise VerifyError('EVIDENCE_COMMON_WINDOW')
	requirement_ids,counterfactual_ids,test_ids,_test_order=freeze_control_sets(freeze);evidence_ids=[item[0]for item in EVIDENCE_SPECS];review_ids=[item[0]for item in REVIEW_SPECS];implementation_plan=[{'path':path,'status':IMPLEMENTATION_PLAN[path]}for path in sorted(IMPLEMENTATION_PLAN,key=lambda item:item.encode('utf-8'))];implementation_paths=[item['path']for item in implementation_entries];expected_path_digest='8a4264751b96c8b1494d4397f143ad3b4e9a13ca8ee5ab53e0a335a738274ff0';snapshot={'freeze_commit':freeze_commit,'freeze_tree':commit_meta(repo,freeze_commit)['tree'],'freeze_regular_blobs':426,'implementation_commit':implementation_commit,'implementation_tree':commit_meta(repo,implementation_commit)['tree'],'implementation_regular_blobs':434,'path_set_sha256':expected_path_digest}
	if len(implementation_paths)!=434 or sha256(canonical_json(implementation_paths))!=expected_path_digest:raise VerifyError('EVIDENCE_IMPLEMENTATION_PATHS')
	projection=composition_projection(composition);e01=evidence['CH-T003-E01'];expected_e01_digests={'implementation_plan_sha256':sha256(canonical_json(implementation_plan)),'requirement_ids_sha256':sha256(canonical_json(requirement_ids)),'test_ids_sha256':sha256(canonical_json(test_ids)),'evidence_ids_sha256':sha256(canonical_json(evidence_ids)),'review_ids_sha256':sha256(canonical_json(review_ids))}
	if e01['implementation_plan']!=implementation_plan or e01['requirement_ids']!=requirement_ids or e01['test_ids']!=test_ids or e01['evidence_ids']!=evidence_ids or e01['review_ids']!=review_ids or e01['snapshot']!=snapshot or e01['composition']!=projection or e01['counts']!={'implementation_paths':9,'requirements':20,'tests':len(test_ids),'evidence':13,'reviews':4}or e01['digests']!=expected_e01_digests:raise VerifyError('E01_CONTENT')
	e02=evidence['CH-T003-E02'];commands=e02['commands'];expected_phases=['PRODUCT_TESTS','PRODUCT_VERIFY','REGISTERED_TESTS','EXACT_IMPLEMENTATION_VERIFY','NEGATIVE_TESTS','TECHNIQUE_TESTS','RESOURCE_SAMPLE_01','RESOURCE_SAMPLE_02','RESOURCE_SAMPLE_03','RESOURCE_SAMPLE_04','RESOURCE_SAMPLE_05']
	if not isinstance(commands,list)or len(commands)!=len(expected_phases)or[item.get('id')for item in commands if isinstance(item,dict)]!=[f"CH-T003-CMD{index:02d}"for index in range(1,len(expected_phases)+1)]or[item.get('phase')for item in commands if isinstance(item,dict)]!=expected_phases:raise VerifyError('E02_COMMAND_SET')
	base_tails={'PRODUCT_TESTS':['-B','-I','-P',PRODUCT_TESTS_PATH],'PRODUCT_VERIFY':['-B','-I','-P',PRODUCT_PATH,'verify','--repo','.','--implementation-commit',implementation_commit],'REGISTERED_TESTS':['-B','-I','-P',TESTS_PATH],'EXACT_IMPLEMENTATION_VERIFY':['-B','-I','-P',VERIFIER_PATH,'--repo','.','--freeze-commit',freeze_commit,'--implementation-commit',implementation_commit,'--implementation-only'],'NEGATIVE_TESTS':['-B','-I','-P',TESTS_PATH,'-k','rejected'],'TECHNIQUE_TESTS':['-B','-I','-P',TESTS_PATH,'-k','technique_']};base_tails.update({f"RESOURCE_SAMPLE_{index:02d}":base_tails['EXACT_IMPLEMENTATION_VERIFY']for index in range(1,6)});command_ids:set[str]=set()
	for(command,phase)in zip(commands,expected_phases,strict=True):
		validate_retained_command(command,window_start=implementation_time,window_end=qualification_time,expected_phase=phase);argv=command['argv'];executable=Path(argv[0])
		if command['id']in command_ids or not executable.is_absolute()or not executable.name.startswith('python3.14')or argv[1:]!=base_tails[phase]:raise VerifyError('E02_COMMAND_BINDING')
		command_ids.add(command['id'])
	environment=require_fields(e02['environment'],{'architecture','git_version','platform','python_version'},'e02_environment')
	if environment['architecture']not in{'arm64','aarch64'}or not environment['git_version'].startswith('git version ')or not isinstance(environment['platform'],str)or not environment['platform']or re.fullmatch('CPython 3\\.14\\.\\d+',environment['python_version'])is None:raise VerifyError('E02_ENVIRONMENT')
	controls=freeze['normative_controls'];counterfactuals=freeze['mandatory_counterfactuals'];e03=evidence['CH-T003-E03']
	def vector(item:dict[str,Any],accepted:bool)->dict[str,Any]:return{'id':item['id'],'test_id':item['accepted_test_id'if accepted else'rejected_test_id'],'result':'PASS'}
	if e03['accepted_vectors']!=[vector(item,True)for item in controls]or e03['rejected_vectors']!=[vector(item,False)for item in controls]or e03['accepted_counterfactuals']!=[vector(item,True)for item in counterfactuals]or e03['rejected_counterfactuals']!=[vector(item,False)for item in counterfactuals]or e03['command_ids']!=[item['id']for item in commands[:6]]:raise VerifyError('E03_VECTORS')
	technique_tests={'BOUNDARY':['test_resource_exact_json_boundary','test_resource_path_boundary','test_resource_language_hit_boundary'],'METAMORPHIC':['test_technique_metamorphic_path_order'],'DIFFERENTIAL':['test_technique_differential_claim_hash'],'MUTATION':['test_technique_mutation_changes_digest'],'HOSTILE_ARCHIVE':['test_archive_path_traversal_is_rejected','test_archive_duplicate_member_is_rejected','test_concatenated_gzip_is_rejected'],'PROPERTY':[*test_ids,'test_technique_property_canonical_json_is_permutation_invariant','test_technique_property_canonical_json_mutation_is_detectable'],'DETERMINISTIC_SEEDED_FUZZ':['test_technique_deterministic_seeded_fuzz_json_roundtrip','test_technique_deterministic_seeded_fuzz_path_policy']};e04=evidence['CH-T003-E04'];techniques=e04['techniques']
	if not isinstance(techniques,list)or[item.get('kind')for item in techniques if isinstance(item,dict)]!=list(TECHNIQUE_KINDS)or e04['covered_requirement_ids']!=requirement_ids or e04['covered_counterfactual_ids']!=counterfactual_ids:raise VerifyError('E04_TECHNIQUES')
	expected_covered_tests:set[str]=set()
	for item in techniques:
		item=require_fields(item,{'kind','status','test_ids','command_ids','covered_requirement_ids','covered_counterfactual_ids','limitations'},'e04_technique');expected_test_paths=[f"{TESTS_PATH}::{test_id}"for test_id in technique_tests[item['kind']]];expected_command=commands[5]['id']if item['kind']in{'METAMORPHIC','DIFFERENTIAL','MUTATION'}else commands[2]['id']
		if item['status']!='PASS'or item['test_ids']!=expected_test_paths or item['command_ids']!=[expected_command]or item['covered_requirement_ids']!=requirement_ids or item['covered_counterfactual_ids']!=counterfactual_ids or not isinstance(item['limitations'],list)or not item['limitations']or not all(isinstance(limit,str)and limit for limit in item['limitations']):raise VerifyError('E04_TECHNIQUE_BINDING')
		expected_covered_tests.update(expected_test_paths)
	if e04['covered_test_ids']!=sorted(expected_covered_tests,key=lambda item:item.encode('utf-8')):raise VerifyError('E04_TEST_COVERAGE')
	e05=evidence['CH-T003-E05'];distributions=require_fields(e05['observed_distributions'],{'real_seconds','peak_rss_bytes'},'e05_distributions');real_seconds=distributions['real_seconds'];rss_values=distributions['peak_rss_bytes']
	if e05['declared_maxima']!={'command_seconds':1800,'github_body_bytes':4194304,'github_total_bytes':16777216,'implementation_regular_blobs':434,'output_bytes':4194304,'resource_samples':5,'stream_bytes':4194304}or not isinstance(real_seconds,list)or len(real_seconds)!=5 or not all(type(item)in{int,float}and math.isfinite(item)and item>=0 and item<=1800 for item in real_seconds)or not isinstance(rss_values,list)or len(rss_values)!=5 or not all(type(item)is int and item>0 for item in rss_values)or e05['observed_maxima']!={'commands':len(commands),'implementation_aggregate_blob_bytes':sum(len(payload)for payload in implementation_blobs.values()),'largest_implementation_blob_bytes':max(len(payload)for payload in implementation_blobs.values()),'peak_rss_bytes':max(rss_values),'resource_real_seconds':max(real_seconds),'implementation_regular_blobs':434}or e05['command_ids']!=[item['id']for item in commands]or e05['capacity_disposition']!={'fallback_permitted':False,'hard_ceiling_success_claimed':False,'qualified_candidate_only':True,'result':'PASS'}:raise VerifyError('E05_RESOURCES')
	e06=evidence['CH-T003-E06'];registered_paths=FREEZE_PATH,REGISTRY_PATH,TESTS_PATH,VERIFIER_PATH;registered_files=[exact_file_record(path,freeze_entries,freeze_blobs)for path in registered_paths];implementation_files=[exact_file_record(path,implementation_entries,implementation_blobs)for path in sorted(IMPLEMENTATION_PLAN,key=lambda item:item.encode('utf-8'))];prior_entries,prior_blobs=tree_snapshot(repo,PRIOR_ACTIVATION);prior_artifacts=[exact_file_record(path,prior_entries,prior_blobs)for path in('audit/generated/CH-T002_FILE_REVIEW_OVERLAY.json','release/0.9.0/current-head/tasks/ch-t002/e0002/qualification.json')];lifecycle_diffs={'prior_activation_to_freeze':changed_statuses(repo,PRIOR_ACTIVATION,freeze_commit),'freeze_to_implementation':changed_statuses(repo,freeze_commit,implementation_commit)};cargo=public['cargo'];public_toolchain=cargo['toolchain'];tool_identities={'python':environment['python_version'],'git':environment['git_version'],'rustc':public_toolchain['tools']['rustc'],'cargo':public_toolchain['tools']['cargo'],'cargo_public_api':public_toolchain['cargo_public_api']};tree_snapshot_value={'regular_blob_count':434,'aggregate_blob_bytes':sum(len(payload)for payload in implementation_blobs.values()),'path_set_sha256':expected_path_digest};e06_values={'registered_files':registered_files,'implementation_files':implementation_files,'prior_artifacts':prior_artifacts,'tree_snapshot':tree_snapshot_value,'lifecycle_diffs':lifecycle_diffs,'tool_identities':tool_identities}
	if e06['baseline_commit']!=PRIOR_ACTIVATION or e06['prior_lifecycle']!={'freeze_commit':PRIOR_FREEZE,'implementation_commit':PRIOR_IMPLEMENTATION,'qualification_commit':PRIOR_QUALIFICATION,'activation_commit':PRIOR_ACTIVATION}or e06['freeze_tree']!=snapshot['freeze_tree']or e06['implementation_tree']!=snapshot['implementation_tree']or any(e06[key]!=value for(key,value)in e06_values.items())or e06['digests']!={f"{key}_sha256":sha256(canonical_json(value))for(key,value)in e06_values.items()}:raise VerifyError('E06_IDENTITIES')
	tier_records=tier['records'];narrowed_records=[item for item in tier_records if item['id']==NARROWED_CLAIM]
	if len(narrowed_records)!=1:raise VerifyError('E07_NARROWED_RECORD')
	narrowed=narrowed_records[0];prior_rows={item['id']:item for item in parse_claim_rows(freeze_blobs[CLAIM_LEDGER_PATH])}
	if NARROWED_CLAIM not in prior_rows:raise VerifyError('E07_PRIOR_CLAIM')
	prior_narrowed=prior_rows[NARROWED_CLAIM];claim_transition={'claim_id':NARROWED_CLAIM,'before_status':prior_narrowed['status'],'after_status':narrowed['status'],'before_statement_sha256':prior_narrowed['statement_sha256'],'after_statement_sha256':narrowed['statement_sha256'],'evidence_tier':narrowed['evidence_tier'],'release_qualified':narrowed['release_qualified']}
	if claim_transition['before_status']!='PROVEN'or claim_transition['after_status']!='PROVEN'or claim_transition['before_statement_sha256']==claim_transition['after_statement_sha256']or claim_transition['evidence_tier']!='VERIFIED'or claim_transition['release_qualified']is not False:raise VerifyError('E07_CLAIM_TRANSITION_BINDING')
	outcomes=freeze.get('claim_outcomes')
	if not isinstance(outcomes,list)or len(outcomes)!=1:raise VerifyError('FREEZE_OUTCOME')
	outcome=outcomes[0];e07=evidence['CH-T003-E07']
	if e07['claim_outcome']!=outcome or e07['implementation_paths']!=implementation_plan or e07['claim_transition']!=claim_transition or e07['runtime_surface_changed']is not False or e07['release_authority']is not None or e07['publication_authority']is not None or e07['requirements_complete']is not True:raise VerifyError('E07_CLAIM_TRANSITION')
	e08=evidence['CH-T003-E08'];public_records={item['path']:item for item in public['records']};assignments:list[dict[str,Any]]=[];completions:list[dict[str,Any]]=[];common_started=next(iter(common_starts));common_completed=next(iter(common_completions));entry_by_path={item['path']:item for item in implementation_entries}
	for path in implementation_paths:entry=entry_by_path[path];payload=implementation_blobs[path];primary,secondary=assigned_review_lanes(path);evidence_for_path=assignment_evidence_ids(path);assignments.append({'path':path,'git_mode':entry['git_mode'],'git_object_id':entry['git_object_id'],'sha256':sha256(payload),'bytes':len(payload),'content_kind':public_records.get(path,{}).get('content_kind',qualification_content_kind(path,payload)),'provenance_category':'CH_T003_IMPLEMENTATION'if path in IMPLEMENTATION_PLAN else'SIGNED_F_BASELINE','primary_review_id':primary,'secondary_review_id':secondary,'evidence_ids':evidence_for_path,'assigned_at_utc':common_started});completions.append({'path':path,'primary_review_id':primary,'secondary_review_id':secondary,'completed_at_utc':common_completed,'status':'REVIEWED','evidence_ids':evidence_for_path})
	if e08['snapshot']!=snapshot or e08['composition']!=projection or e08['assignments']!=assignments or e08['completion_records']!=completions or e08['counts']!={'snapshot_paths':434,'assignments':434,'completions':434,'primary_review_lanes':3,'secondary_review_lanes':3,'gaps':0,'duplicates':0}or e08['digests']!={'path_set_sha256':expected_path_digest,'assignments_sha256':sha256(canonical_json(assignments)),'completion_records_sha256':sha256(canonical_json(completions)),'composition_sha256':sha256(canonical_json(projection))}or e08['review_boundary']!=REVIEW_BOUNDARY:raise VerifyError('E08_REVIEW_LEDGER')
	public_source=exact_file_record(PUBLIC_INVENTORY_PATH,implementation_entries,implementation_blobs);e09=evidence['CH-T003-E09']
	if e09['source_file']!=public_source or e09['policy']!=public['policy']or e09['counts']!=public['counts']or e09['digests']!=public['digests']or e09['section_results']!=evidence_section_results(public)or not isinstance(e09['limitations'],list)or len(e09['limitations'])!=3 or not all(isinstance(item,str)and item for item in e09['limitations']):raise VerifyError('E09_PUBLIC_INVENTORY')
	prior_claims=load_json(freeze_blobs[CLAIMS_STATE_PATH],canonical=False);e10=evidence['CH-T003-E10'];expected_release_boundary={'release_qualified_claims':[],'tag_authorized':False,'github_release_authorized':False,'doi_authorized':False,'zenodo_authorized':False,'archive_authorized':False,'release_authority':None}
	if e10['source_file']!=exact_file_record(CLAIM_TIER_PATH,implementation_entries,implementation_blobs)or e10['claim_ledger']!=exact_file_record(CLAIM_LEDGER_PATH,implementation_entries,implementation_blobs)or e10['prior_active_claims']!={'file':exact_file_record(CLAIMS_STATE_PATH,freeze_entries,freeze_blobs),'verified_prefix':prior_claims['verified_prefix'],'active_claims':prior_claims['active_claims'],'narrowed_claims':prior_claims['narrowed_claims']}or e10['counts']!=tier['counts']or e10['digests']!={**tier['bidirectional_links'],'records_sha256':tier['records_sha256'],'source_file_sha256':sha256(implementation_blobs[CLAIM_TIER_PATH])}or e10['tier_vocabulary']!=tier['tier_vocabulary']or e10['transition']!=claim_transition or e10['release_boundary']!=expected_release_boundary:raise VerifyError('E10_CLAIM_TIER')
	e11=evidence['CH-T003-E11']
	if e11['source_file']!=exact_file_record(GITHUB_METADATA_PATH,implementation_entries,implementation_blobs)or e11['capture_window']!={'captured_at_utc':github['captured_at_utc'],'freeze_commit':freeze_commit,'implementation_commit':implementation_commit,'chronology':'AFTER_SIGNED_F_AND_BEFORE_SIGNED_I'}or e11['capture_policy']!=github['request_policy']or e11['endpoints']!=github['endpoint_summary']or e11['normalized']!=github['normalized']or e11['digests']!={'captures_sha256':github['captures_sha256'],'source_file_sha256':sha256(implementation_blobs[GITHUB_METADATA_PATH])}or e11['redaction_boundary']!={'authorization_retained':False,'cookies_retained':False,'environment_retained':False,'safe_response_metadata_retained':['status','etag','link','bytes','sha256']}:raise VerifyError('E11_GITHUB_METADATA')
	validate_hosted_implementation_capture(evidence['CH-T003-E12'],implementation_commit=implementation_commit,implementation_entries=implementation_entries,implementation_blobs=implementation_blobs);e13=evidence['CH-T003-E13'];public_api=cargo['public_api'];observations=public_api['observations'];documents=public_api['documents'];targets=sorted({item['target']for item in observations},key=lambda item:item.encode('utf-8'));profiles=sorted({item['configuration']for item in observations},key=lambda item:item.encode('utf-8'));macro_invariant=public_api['macro_invariant'];source_cross_checks={'exported_macros':list(EXPORTED_MACROS),'exported_macros_complete':True,'public_constant_present':'HARD_MAX_INTENT_BYTES','private_constants_absent':list(PRIVATE_CONSTANTS),'private_constants_absent_from_compiler_output':True,'macro_invariant':macro_invariant}
	if len(observations)!=100 or len(targets)!=2 or e13['source_file']!=public_source or e13['toolchain']!=cargo['toolchain']or e13['lockfile']!=exact_file_record('Cargo.lock',implementation_entries,implementation_blobs)or e13['targets']!=targets or e13['profiles']!=profiles or e13['commands']!=observations or e13['api_sets']!=documents or e13['source_cross_checks']!=source_cross_checks or e13['digests']!={'commands_sha256':sha256(canonical_json(observations)),'api_sets_sha256':sha256(canonical_json(documents)),'source_cross_checks_sha256':sha256(canonical_json(macro_invariant))}or not isinstance(e13['limitations'],list)or len(e13['limitations'])!=3:raise VerifyError('E13_COMPILER_API')
	compiler_text=canonical_json(documents)
	if any(name.encode('ascii')not in canonical_json(macro_invariant)for name in EXPORTED_MACROS)or any(name.encode('ascii')in compiler_text for name in PRIVATE_CONSTANTS):raise VerifyError('E13_EXPORT_BOUNDARY')
	outer_records=qualification['evidence_records']
	if not isinstance(outer_records,list)or len(outer_records)!=len(EVIDENCE_SPECS):raise VerifyError('QUALIFICATION_EVIDENCE_RECORDS')
	expected_outer:list[dict[str,Any]]=[]
	for(identifier,kind,_name,_schema)in EVIDENCE_SPECS:document=evidence[identifier];expected_outer.append({'completed_at_utc':document['completed_at_utc'],'file':exact_file_record(EVIDENCE_PATHS[identifier],qualification_entries,qualification_blobs),'id':identifier,'kind':kind,'result':'PASS','started_at_utc':document['started_at_utc'],'subject_commits':[freeze_commit,implementation_commit]})
	for item in outer_records:require_fields(item,EVIDENCE_RECORD_FIELDS,'evidence_record')
	if outer_records!=expected_outer:raise VerifyError('QUALIFICATION_EVIDENCE_WRAPPERS')
	return evidence
def validate_qualification_reviews(*,repo:Path,freeze_commit:str,implementation_commit:str,qualification_commit:str,freeze:dict[str,Any],qualification:dict[str,Any],freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes],implementation_entries:list[dict[str,Any]],implementation_blobs:dict[str,bytes],qualification_entries:list[dict[str,Any]],qualification_blobs:dict[str,bytes],evidence:dict[str,dict[str,Any]])->None:
	registry=reviewer_registry(freeze);implementation_files=[exact_file_record(path,implementation_entries,implementation_blobs)for path in sorted(IMPLEMENTATION_PLAN,key=lambda item:item.encode('utf-8'))];context_paths=FREEZE_PATH,REGISTRY_PATH,TESTS_PATH,VERIFIER_PATH,'tools/release/verify-current-audit.py','tools/verify-claims.py';context_records=[]
	for path in context_paths:
		if path in freeze_blobs:context_records.append(exact_file_record(path,freeze_entries,freeze_blobs))
		else:context_records.append(exact_file_record(path,implementation_entries,implementation_blobs))
	requirement_by_id={item['id']:item for item in freeze['review_requirements']};outer_records=qualification['review_records']
	if not isinstance(outer_records,list)or len(outer_records)!=4 or[item.get('id')for item in outer_records if isinstance(item,dict)]!=[item[0]for item in REVIEW_SPECS]:raise VerifyError('QUALIFICATION_REVIEW_RECORDS')
	evidence_end=max(parse_utc(item['completed_at_utc'])for item in evidence.values());qualification_time=commit_time(repo,qualification_commit);base_tails={'PRODUCT_TESTS':['-B','-I','-P',PRODUCT_TESTS_PATH],'PRODUCT_VERIFY':['-B','-I','-P',PRODUCT_PATH,'verify','--repo','.','--implementation-commit',implementation_commit],'REGISTERED_TESTS':['-B','-I','-P',TESTS_PATH],'EXACT_IMPLEMENTATION_VERIFY':['-B','-I','-P',VERIFIER_PATH,'--repo','.','--freeze-commit',freeze_commit,'--implementation-commit',implementation_commit,'--implementation-only'],'NEGATIVE_TESTS':['-B','-I','-P',TESTS_PATH,'-k','rejected'],'TECHNIQUE_TESTS':['-B','-I','-P',TESTS_PATH,'-k','technique_']};evidence_ids=[item[0]for item in EVIDENCE_SPECS];evidence_set_sha256=sha256(canonical_json([{'evidence_id':identifier,'path':EVIDENCE_PATHS[identifier],'bytes':len(qualification_blobs[EVIDENCE_PATHS[identifier]]),'sha256':sha256(qualification_blobs[EVIDENCE_PATHS[identifier]])}for(identifier,_kind,_name,_schema)in EVIDENCE_SPECS]));provenance_values:list[tuple[str,str,str,str]]=[];findings_by_id:dict[str,list[str]]={};limitations_by_id:dict[str,list[str]]={}
	for(index,((identifier,kind,_name),outer))in enumerate(zip(REVIEW_SPECS,outer_records,strict=True)):
		outer=require_fields(outer,REVIEW_RECORD_FIELDS,'qualification_review_record');report=load_json(qualification_blobs[REVIEW_PATHS[identifier]]);report=require_fields(report,REVIEW_REPORT_FIELDS,'qualification_review_report');requirement=requirement_by_id.get(identifier);registry_item=registry[identifier];expected_requirement={'id':requirement['id'],'kind':requirement['kind'],'path':requirement['path']};reproduction=require_fields(report['decisive_reproduction'],{'commands','evidence_ids','result'},'review_reproduction');phases=REVIEW_PHASES[identifier];serialized_commands=require_string_list(reproduction['commands'],f"review_reproduction_commands.{identifier}",nonempty=True,unique=True)
		if reproduction['evidence_ids']!=evidence_ids or reproduction['result']!='PASS'or len(serialized_commands)!=len(phases)+1 or any(len(item.encode('utf-8'))>4096 for item in serialized_commands):raise VerifyError(f"REVIEW_REPRODUCTION:{identifier}")
		binding=load_json(serialized_commands[0].encode('utf-8'))
		if binding!={'evidence_set_sha256':evidence_set_sha256,'kind':'EVIDENCE_SET_BINDING'}:raise VerifyError(f"REVIEW_EVIDENCE_BINDING:{identifier}")
		review_commands=[load_json(item.encode('utf-8'))for item in serialized_commands[1:]]
		if[item.get('id')for item in review_commands if isinstance(item,dict)]!=[f"{identifier}-CMD{command_index:02d}"for command_index in range(1,len(phases)+1)]:raise VerifyError(f"REVIEW_REPRODUCTION:{identifier}")
		previous_completed=evidence_end;exact_results=0
		for(command,phase)in zip(review_commands,phases,strict=True):
			command_started,command_completed=validate_retained_command(command,window_start=evidence_end,window_end=qualification_time,expected_phase=phase);argv=command['argv'];executable=Path(argv[0])
			if command_started<previous_completed or not executable.is_absolute()or not executable.name.startswith('python3.14')or argv[1:]!=base_tails[phase]:raise VerifyError(f"REVIEW_COMMAND:{identifier}")
			previous_completed=command_completed
			if phase=='EXACT_IMPLEMENTATION_VERIFY':
				exact=load_json(command['stdout'].encode('utf-8'))
				if not isinstance(exact,dict)or exact.get('result')!='PASS'or exact.get('freeze_commit')!=freeze_commit or exact.get('implementation_commit')!=implementation_commit:raise VerifyError(f"REVIEW_EXACT_RESULT:{identifier}")
				exact_results+=1
		if exact_results!=1:raise VerifyError(f"REVIEW_EXACT_RESULT:{identifier}")
		provenance=require_fields(report['reviewer_provenance'],{'method','session_id','tool','version'},'review_provenance');expected_method='AUTOMATED_LEAD_SUPPORT_REPRODUCTION'if identifier=='CH-T003-R04'else'INDEPENDENT_EXACT_ARTIFACT_REPRODUCTION'
		if provenance['method']!=expected_method or any(not isinstance(value,str)or not value.strip()or value!=value.strip()or len(value.encode('utf-8'))>256 for value in provenance.values())or identifier=='CH-T003-R04'and(provenance['tool']!='prepare-ch-t003-c'or provenance['version']!='2.0.0'):raise VerifyError(f"REVIEW_PROVENANCE:{identifier}")
		findings=require_string_list(report['findings'],f"review_findings.{identifier}",nonempty=True,unique=True);limitations=require_string_list(report['limitations'],f"review_limitations.{identifier}",nonempty=True,unique=True)
		if any(text!=text.strip()or len(text.encode('utf-8'))>4096 for text in[*findings,*limitations]):raise VerifyError(f"REVIEW_AUTHORED_TEXT:{identifier}")
		provenance_values.append((provenance['method'],provenance['session_id'],provenance['tool'],provenance['version']));findings_by_id[identifier]=findings;limitations_by_id[identifier]=limitations
		if report['schema_version']!='1.0.0'or report['task_id']!=TASK_ID or report['epoch']!=EPOCH or report['requirement']!=expected_requirement or report['reviewer']!=registry_item['reviewer']or report['freeze_commit']!=freeze_commit or report['implementation_commit']!=implementation_commit or report['implementation_diff']!={'statuses':IMPLEMENTATION_PLAN,'changed_file_records':implementation_files,'deleted_paths':[]}or report['all_changed_lines_reviewed']is not True or report['reviewed_relevant_context']!=context_records or report['relevant_unchanged_context_reviewed']is not True or report['decision']!='ACCEPT_TECHNICAL_TASK_QUALIFICATION':raise VerifyError(f"REVIEW_REPORT:{identifier}")
		started=parse_utc(outer['started_at_utc']);completed=parse_utc(outer['completed_at_utc']);lead=index==3;namespace='haldir-automated-lead-support-v2'if lead else'haldir-independent-review-v2';signature=require_fields(outer['detached_signature'],{'format','namespace','principal','public_key','key_fingerprint','signature'},'review_signature')
		if outer['kind']!=kind or outer['file']!=exact_file_record(REVIEW_PATHS[identifier],qualification_entries,qualification_blobs)or outer['reviewer']!=registry_item['reviewer']or outer['independent_from_release_author']is not(not lead)or outer['external']is not False or outer['human']is not False or outer['named_human_reviewer']is not False or outer['release_approver']is not False or outer['reproduced_decisive_evidence']is not True or outer['reviewed_all_changed_lines_and_context']is not True or outer['decision']!='ACCEPT_TECHNICAL_TASK_QUALIFICATION'or outer['started_at_utc']!=review_commands[0]['started_at_utc']or not evidence_end<=started<=completed<=qualification_time or completed<previous_completed or signature['format']!='ssh'or signature['namespace']!=namespace or signature['principal']!=registry_item['reviewer']['principal']or signature['public_key']!=registry_item['public_key']or signature['key_fingerprint']!=registry_item['key_fingerprint']:raise VerifyError(f"REVIEW_RECORD:{identifier}")
		verify_review_signature(registry_item,namespace,signature['signature'],review_attestation_payload(outer,freeze_commit,implementation_commit))
	if len(set(provenance_values))!=len(REVIEW_SPECS)or len({item[1]for item in provenance_values})!=len(REVIEW_SPECS)or len({sha256(canonical_json(findings_by_id[identifier]))for identifier in('CH-T003-R01','CH-T003-R02','CH-T003-R03')})!=3 or len({sha256(canonical_json(limitations_by_id[identifier]))for identifier in('CH-T003-R01','CH-T003-R02','CH-T003-R03')})!=3:raise VerifyError('REVIEW_INDEPENDENCE')
	qualification_limitations=qualification['limitations']
	if not isinstance(qualification_limitations,list)or any(limitation not in qualification_limitations for values in limitations_by_id.values()for limitation in values):raise VerifyError('REVIEW_LIMITATION_BINDING')
	dispositions=qualification['review_finding_dispositions'];disposition_evidence={'CH-T003-R01':['CH-T003-E01','CH-T003-E06','CH-T003-E08'],'CH-T003-R02':['CH-T003-E07','CH-T003-E10'],'CH-T003-R03':['CH-T003-E09','CH-T003-E13'],'CH-T003-R04':['CH-T003-E02','CH-T003-E12']}
	if not isinstance(dispositions,list)or len(dispositions)!=4 or[item.get('review_id')for item in dispositions if isinstance(item,dict)]!=[item[0]for item in REVIEW_SPECS]:raise VerifyError('REVIEW_DISPOSITIONS')
	for item in dispositions:
		identifier=item['review_id'];item=require_fields(item,{'disposition','evidence_ids','finding','rationale','residual_limitation','review_id'},'review_disposition')
		if item['disposition']!='RESOLVED'or item['evidence_ids']!=disposition_evidence[identifier]or item['finding']!=findings_by_id[identifier][0]or not isinstance(item['rationale'],str)or not item['rationale']or item['residual_limitation']is not None:raise VerifyError('REVIEW_DISPOSITION_BINDING')
def validate_qualification_stage(repo:Path,freeze_commit:str,implementation_commit:str,qualification_commit:str)->dict[str,Any]:
	freeze_entries,freeze_blobs=tree_snapshot(repo,freeze_commit);implementation_entries,implementation_blobs=tree_snapshot(repo,implementation_commit);qualification_entries,qualification_blobs=tree_snapshot(repo,qualification_commit);freeze=load_json(freeze_blobs[FREEZE_PATH],canonical=False)
	if not isinstance(freeze,dict):raise VerifyError('FREEZE_SHAPE')
	qualification=require_fields(load_json(qualification_blobs[QUALIFICATION_PATH]),QUALIFICATION_FIELDS,'qualification')
	if qualification['schema_version']!='1.0.0'or qualification['task_id']!=TASK_ID or qualification['epoch']!=EPOCH or qualification['release_target']!=RELEASE_TARGET or qualification['author']!=AUTHOR or qualification['persistent_identifier']is not None or qualification['effective_on']!='SIGNED_COMMIT_FIRST_CONTAINING_EXACT_QUALIFICATION_EVIDENCE_AND_REVIEWS'or qualification['freeze_commit']!=freeze_commit or qualification['implementation_commit']!=implementation_commit or qualification['selected_claim_outcome_id']!=OUTCOME_ID or qualification['release_authority']is not None or qualification['human_review_boundary']!=REVIEW_BOUNDARY:raise VerifyError('QUALIFICATION_IDENTITY')
	limitations=require_string_list(qualification['limitations'],'qualification_limitations',nonempty=True,unique=True,sorted_utf8=True)
	if not any('No release'in item for item in limitations)or any(word in canonical_json(qualification).decode('utf-8').casefold()for word in('sk-ant-','github_pat_','anthropic_api_key')):raise VerifyError('QUALIFICATION_LIMITATIONS')
	registered=require_fields(qualification['registered_files'],{'freeze_contract','tests','verifier'},'qualification_registered_files')
	if registered!={'freeze_contract':exact_file_record(FREEZE_PATH,freeze_entries,freeze_blobs),'tests':exact_file_record(TESTS_PATH,freeze_entries,freeze_blobs),'verifier':exact_file_record(VERIFIER_PATH,freeze_entries,freeze_blobs)}:raise VerifyError('QUALIFICATION_REGISTERED_FILES')
	evidence=validate_qualification_evidence(repo=repo,freeze_commit=freeze_commit,implementation_commit=implementation_commit,qualification_commit=qualification_commit,freeze=freeze,qualification=qualification,freeze_entries=freeze_entries,freeze_blobs=freeze_blobs,implementation_entries=implementation_entries,implementation_blobs=implementation_blobs,qualification_entries=qualification_entries,qualification_blobs=qualification_blobs);validate_qualification_reviews(repo=repo,freeze_commit=freeze_commit,implementation_commit=implementation_commit,qualification_commit=qualification_commit,freeze=freeze,qualification=qualification,freeze_entries=freeze_entries,freeze_blobs=freeze_blobs,implementation_entries=implementation_entries,implementation_blobs=implementation_blobs,qualification_entries=qualification_entries,qualification_blobs=qualification_blobs,evidence=evidence);lenses=qualification['twenty_lens_reviews'];frozen_lenses=freeze.get('lens_questions')
	if not isinstance(lenses,dict)or list(lenses)!=[f"L{index:02d}"for index in range(1,21)]or not isinstance(frozen_lenses,list)or len(frozen_lenses)!=20:raise VerifyError('QUALIFICATION_LENSES')
	requirement_ids,counterfactual_ids,_test_ids,_test_order=freeze_control_sets(freeze);evidence_ids={item[0]for item in EVIDENCE_SPECS};review_ids=[item[0]for item in REVIEW_SPECS]
	for(frozen,(identifier,item))in zip(frozen_lenses,lenses.items(),strict=True):
		item=require_fields(item,{'claim_impact','control_ids','counterfactual_ids','evidence_ids','finding','name','question','residual_limitation','reviewer_ids','status'},'qualification_lens')
		if frozen.get('id')!=identifier or item['name']!=frozen.get('name')or item['question']!=frozen.get('question')or item['claim_impact']!='PUBLIC_CLAIMS_NARROWED'or item['status']!='RESOLVED'or item['reviewer_ids']!=review_ids or not isinstance(item['finding'],str)or not item['finding']or item['residual_limitation']not in limitations or not isinstance(item['control_ids'],list)or not set(item['control_ids']).issubset(requirement_ids)or not item['control_ids']or not isinstance(item['counterfactual_ids'],list)or not set(item['counterfactual_ids']).issubset(counterfactual_ids)or not item['counterfactual_ids']or not isinstance(item['evidence_ids'],list)or not set(item['evidence_ids']).issubset(evidence_ids)or not item['evidence_ids']:raise VerifyError(f"QUALIFICATION_LENS:{identifier}")
	return qualification
def activation_log_manifest(payload:bytes,job_log_captures:list[dict[str,Any]])->list[dict[str,Any]]:
	expected_names=[JOB_LOG_MEMBERS[name]for name in ALL_HOSTED_JOB_NAMES]
	if not 0<len(payload)<2097152 or len(job_log_captures)!=len(ALL_HOSTED_JOB_NAMES)or[item.get('retained_member')for item in job_log_captures if isinstance(item,dict)]!=expected_names:raise VerifyError('ACTIVATION_LOG_ARCHIVE_BOUND')
	inspect_archive(ACTIVATION_PATHS['CH-T003-A05'],payload)
	try:
		with zipfile.ZipFile(io.BytesIO(payload))as archive:
			entries=archive.infolist()
			if len(entries)!=len(expected_names)or[entry.filename for entry in entries]!=expected_names or archive.comment:raise VerifyError('ACTIVATION_LOG_ARCHIVE_ENTRIES')
			expanded=0;manifest:list[dict[str,Any]]=[]
			for(capture,entry)in zip(job_log_captures,entries,strict=True):
				name=entry.filename;mode=entry.external_attr>>16
				if not valid_archive_member_path(name)or PurePosixPath(name).name!=name or entry.is_dir()or entry.flag_bits!=0 or entry.compress_type!=zipfile.ZIP_STORED or entry.create_system!=3 or entry.date_time!=(1980,1,1,0,0,0)or entry.extra or entry.comment or mode!=stat.S_IFREG|420 or entry.file_size!=capture['bytes']or entry.compress_size!=capture['bytes']or not 0<entry.file_size<=4194304:raise VerifyError('ACTIVATION_LOG_ARCHIVE_ENTRY')
				expanded+=entry.file_size
				if expanded>4194304:raise VerifyError('ACTIVATION_LOG_ARCHIVE_EXPANDED')
				content=archive.read(entry)
				if len(content)!=entry.file_size or sha256(content)!=capture['sha256']:raise VerifyError('ACTIVATION_LOG_ARCHIVE_CONTENT')
				try:content.decode('utf-8','strict')
				except UnicodeDecodeError as error:raise VerifyError('ACTIVATION_LOG_ARCHIVE_TEXT')from error
				normalized_content=ANSI_SGR.sub(b'',content)
				try:normalized_text=normalized_content.decode('utf-8','strict')
				except UnicodeDecodeError as error:raise VerifyError('ACTIVATION_LOG_ARCHIVE_TEXT')from error
				folded_content=normalized_content.lower()
				if b'\x00'in content or b'\x1b'in normalized_content or PROHIBITED_GOVERNANCE_TOKEN in folded_content or b'anthropic_api_key'in folded_content or any(unicodedata.category(character)in{'Cc','Cf','Cs'}and character not in{'\n','\r','\t'}for character in normalized_text)or any(pattern.search(normalized_content)for pattern in SECRET_OUTPUT_PATTERNS):raise VerifyError('ACTIVATION_LOG_ARCHIVE_SENSITIVE')
				manifest.append({'bytes':entry.file_size,'crc32':entry.CRC,'method':entry.compress_type,'mode':mode,'name':name,'sha256':sha256(content)})
			if archive.testzip()is not None:raise VerifyError('ACTIVATION_LOG_ARCHIVE_CRC')
	except VerifyError:raise
	except(OSError,RuntimeError,zipfile.BadZipFile)as error:raise VerifyError('ACTIVATION_LOG_ARCHIVE_INVALID')from error
	eocd_offset=payload.rfind(b'PK\x05\x06')
	if eocd_offset<0 or eocd_offset+22>len(payload):raise VerifyError('ACTIVATION_LOG_ARCHIVE_EOCD')
	comment_bytes=int.from_bytes(payload[eocd_offset+20:eocd_offset+22],'little')
	if eocd_offset+22+comment_bytes!=len(payload):raise VerifyError('ACTIVATION_LOG_ARCHIVE_TRAILING_BYTES')
	return manifest
def decode_retained_capture(value:Any,*,expected_kind:str,expected_source_url:str,qualification_time:datetime,activation_time:datetime)->tuple[dict[str,Any],bytes]:
	record=require_fields(value,{'bytes','capture_argv','completed_at_utc','content_base64','exit_code','kind','media_type','request_headers','sha256','source_url','started_at_utc','stderr','stderr_sha256','tool_version'},'activation_retained_capture')
	try:payload=base64.b64decode(record['content_base64'],validate=True)
	except(TypeError,ValueError)as error:raise VerifyError('ACTIVATION_CAPTURE_BASE64')from error
	started=parse_utc(record['started_at_utc']);completed=parse_utc(record['completed_at_utc']);argv=record['capture_argv'];expected_api_path=expected_source_url.removeprefix('https://api.github.com/');expected_tail=['api','--hostname','github.com','--method','GET','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2022-11-28',expected_api_path]
	if record['kind']!=expected_kind or record['source_url']!=expected_source_url or record['media_type']!='application/vnd.github+json'or record['request_headers']!=['Accept: application/vnd.github+json','X-GitHub-Api-Version: 2022-11-28']or type(record['bytes'])is not int or not 0<record['bytes']<=65536 or record['bytes']!=len(payload)or record['sha256']!=sha256(payload)or record['exit_code']!=0 or record['stderr']!=''or record['stderr_sha256']!=sha256(b'')or not isinstance(argv,list)or not argv or not Path(argv[0]).is_absolute()or Path(argv[0]).name!='gh'or argv[1:]!=expected_tail or re.fullmatch('gh version \\d+\\.\\d+\\.\\d+ \\(\\d{4}-\\d{2}-\\d{2}\\)',record['tool_version'])is None or not qualification_time<=started<=completed<=activation_time:raise VerifyError('ACTIVATION_CAPTURE_BINDING')
	return record,payload
def validate_activation_a01(value:Any,*,freeze_commit:str,implementation_commit:str,qualification_commit:str,qualification_time:datetime,activation_time:datetime)->tuple[datetime,datetime]:
	record=require_fields(value,{'checks','commands','completed_at_utc','epoch','evidence_id','freeze_commit','implementation_commit','qualification_commit','result','schema_id','started_at_utc','task_id'},'activation_a01');phases=['PRODUCT_TESTS','PRODUCT_VERIFY','REGISTERED_TESTS','EXACT_IMPLEMENTATION_VERIFY'];started=parse_utc(record['started_at_utc']);completed=parse_utc(record['completed_at_utc'])
	if record['schema_id']!='haldir.ch-t003.subsystem-gate.v1'or record['evidence_id']!='CH-T003-A01'or record['task_id']!=TASK_ID or record['epoch']!=EPOCH or record['freeze_commit']!=freeze_commit or record['implementation_commit']!=implementation_commit or record['qualification_commit']!=qualification_commit or record['result']!='PASS'or record['checks']!=phases or not qualification_time<=started<=completed<=activation_time:raise VerifyError('ACTIVATION_A01_IDENTITY')
	commands=record['commands']
	if not isinstance(commands,list)or len(commands)!=4 or[item.get('id')for item in commands]!=[f"CH-T003-A01-CMD{index:02d}"for index in range(1,5)]or[item.get('phase')for item in commands]!=phases:raise VerifyError('ACTIVATION_A01_COMMANDS')
	tails={'PRODUCT_TESTS':['-B','-I','-P',PRODUCT_TESTS_PATH],'PRODUCT_VERIFY':['-B','-I','-P',PRODUCT_PATH,'verify','--repo','.','--implementation-commit',implementation_commit],'REGISTERED_TESTS':['-B','-I','-P',TESTS_PATH],'EXACT_IMPLEMENTATION_VERIFY':['-B','-I','-P',VERIFIER_PATH,'--repo','.','--freeze-commit',freeze_commit,'--implementation-commit',implementation_commit,'--implementation-only']}
	for(command,phase)in zip(commands,phases,strict=True):
		validate_retained_command(command,window_start=qualification_time,window_end=activation_time,expected_phase=phase);argv=command['argv']
		if not Path(argv[0]).is_absolute()or not Path(argv[0]).name.startswith('python3.14')or argv[1:]!=tails[phase]:raise VerifyError('ACTIVATION_A01_ARGV')
		if phase in{'PRODUCT_VERIFY','EXACT_IMPLEMENTATION_VERIFY'}:
			result=load_json(command['stdout'].encode('utf-8'),canonical=False)
			if not isinstance(result,dict)or result.get('result')!='PASS':raise VerifyError('ACTIVATION_A01_RESULT')
			if phase=='PRODUCT_VERIFY'and(result.get('schema_id')!='haldir.ch-t003.product-verification.v1'or result.get('mode')!='FROZEN_PRODUCT_CHECKS'or command['stderr']):raise VerifyError('ACTIVATION_A01_PRODUCT_RESULT')
			if phase=='EXACT_IMPLEMENTATION_VERIFY'and(result.get('task_id')!=TASK_ID or result.get('freeze_commit')!=freeze_commit or result.get('implementation_commit')!=implementation_commit or result.get('mode')!='IMPLEMENTATION_ONLY'or command['stderr']):raise VerifyError('ACTIVATION_A01_TASK_RESULT')
	return started,completed
def validate_activation_a02(value:Any,*,freeze_commit:str,implementation_commit:str,qualification_commit:str,qualification_time:datetime,activation_time:datetime)->tuple[datetime,datetime]:
	record=require_fields(value,{'command','completed_at_utc','epoch','evidence_id','freeze_commit','implementation_commit','qualification_commit','result','schema_id','scope','started_at_utc','task_id'},'activation_a02');started=parse_utc(record['started_at_utc']);completed=parse_utc(record['completed_at_utc']);expected_argv=['/usr/bin/env','-u','BASH_ENV','-u','ENV','CARGO_TERM_COLOR=never','TERM=dumb','/bin/bash','--noprofile','--norc','tools/p0r-exit-gate.sh']
	if record['schema_id']!='haldir.ch-t003.wave-gate.v2'or record['evidence_id']!='CH-T003-A02'or record['task_id']!=TASK_ID or record['epoch']!=EPOCH or record['freeze_commit']!=freeze_commit or record['implementation_commit']!=implementation_commit or record['qualification_commit']!=qualification_commit or record['result']!='PASS'or record['scope']!={'execution_wave':0,'gate_scope':'FULL_REPOSITORY_LOCKED_GATE_AT_CH_T003_CANDIDATE','remaining_wave_tasks':[f"CH-T{index:03d}"for index in range(4,13)],'wave_acceptance':'NOT_YET_ELIGIBLE'}or not qualification_time<=started<=completed<=activation_time:raise VerifyError('ACTIVATION_A02_IDENTITY')
	command=record['command'];validate_retained_command(command,window_start=qualification_time,window_end=activation_time,expected_phase='WAVE_GATE',expected_argv=expected_argv,maximum_stream_bytes=4194304);lines=command['stdout'].splitlines();pass_lines=[line for line in lines if line.startswith('  PASS: ')];fail_lines=[line for line in lines if line.startswith('  FAIL: ')];summaries=[line for line in lines if line.startswith('P0-R exit gate: ')]
	if command['id']!='CH-T003-A02-CMD01'or command['stderr']!=''or len(pass_lines)!=30 or fail_lines or summaries!=['P0-R exit gate: 30 passed, 0 failed']or lines[-2:]!=[summaries[0],'All offline P0-R gates passed. (TLA+ check runs in CI: CL-FORMAL-01.)']:raise VerifyError('ACTIVATION_A02_TRANSCRIPT')
	return started,completed
def validate_activation_a03(value:Any,*,archive_payload:bytes,freeze_commit:str,implementation_commit:str,qualification_commit:str,qualification_time:datetime,activation_time:datetime)->tuple[datetime,datetime,list[dict[str,Any]]]:
	record=require_fields(value,{'combined_log_archive','completed_at_utc','conclusion','epoch','evidence_id','freeze_commit','head_sha','implementation_commit','provider','qualification_commit','result','schema_id','started_at_utc','task_id','workflows'},'activation_a03');started=parse_utc(record['started_at_utc']);completed=parse_utc(record['completed_at_utc'])
	if record['schema_id']!='haldir.ch-t003.full-locked-ci.v3'or record['evidence_id']!='CH-T003-A03'or record['task_id']!=TASK_ID or record['epoch']!=EPOCH or record['freeze_commit']!=freeze_commit or record['implementation_commit']!=implementation_commit or record['qualification_commit']!=qualification_commit or record['head_sha']!=qualification_commit or record['provider']!='GITHUB_ACTIONS'or record['conclusion']!='success'or record['result']!='PASS'or not qualification_time<=started<=completed<=activation_time:raise VerifyError('ACTIVATION_A03_IDENTITY')
	workflows=record['workflows']
	if not isinstance(workflows,list)or len(workflows)!=len(HOSTED_WORKFLOW_SPECS)or[item.get('workflow_path')for item in workflows if isinstance(item,dict)]!=[item[0]for item in HOSTED_WORKFLOW_SPECS]:raise VerifyError('ACTIVATION_A03_WORKFLOWS')
	all_job_ids:set[int]=set();run_ids:set[int]=set();all_log_captures:list[dict[str,Any]]=[];gh_version:str|None=None;previous_workflow_completed=started
	for(workflow,(workflow_path,job_names))in zip(workflows,HOSTED_WORKFLOW_SPECS,strict=True):
		workflow=require_fields(workflow,{'completed_at_utc','conclusion','head_sha','job_log_captures','jobs','retained_records','run_attempt','run_id','run_url','started_at_utc','workflow_path'},'activation_a03_workflow');workflow_started=parse_utc(workflow['started_at_utc']);workflow_completed=parse_utc(workflow['completed_at_utc']);run_id=workflow['run_id'];run_attempt=workflow['run_attempt'];run_url=f"https://github.com/sepahead/haldir/actions/runs/{run_id}";api_root=f"https://api.github.com/repos/sepahead/haldir/actions/runs/{run_id}"
		if workflow['workflow_path']!=workflow_path or workflow['head_sha']!=qualification_commit or workflow['conclusion']!='success'or type(run_id)is not int or run_id<=0 or run_id in run_ids or type(run_attempt)is not int or run_attempt<=0 or workflow['run_url']!=run_url or not previous_workflow_completed<=workflow_started<=workflow_completed<=completed:raise VerifyError('ACTIVATION_A03_WORKFLOW_IDENTITY')
		previous_workflow_completed=workflow_completed;run_ids.add(run_id);jobs=workflow['jobs']
		if not isinstance(jobs,list)or len(jobs)!=len(job_names)or[item.get('name')for item in jobs]!=list(job_names):raise VerifyError('ACTIVATION_A03_JOBS')
		for item in jobs:
			item=require_fields(item,{'conclusion','job_id','name'},'activation_a03_job')
			if item['conclusion']!='success'or type(item['job_id'])is not int or item['job_id']<=0 or item['job_id']in all_job_ids:raise VerifyError('ACTIVATION_A03_JOB')
			all_job_ids.add(item['job_id'])
		retained=workflow['retained_records']
		if not isinstance(retained,list)or len(retained)!=2:raise VerifyError('ACTIVATION_A03_RETAINED')
		run_capture,run_payload=decode_retained_capture(retained[0],expected_kind='RUN_API_JSON',expected_source_url=api_root,qualification_time=qualification_time,activation_time=activation_time);jobs_source=f"{api_root}/attempts/{run_attempt}/jobs?per_page=100";jobs_capture,jobs_payload=decode_retained_capture(retained[1],expected_kind='ATTEMPT_JOBS_API_JSON',expected_source_url=jobs_source,qualification_time=qualification_time,activation_time=activation_time)
		if not workflow_started<=parse_utc(run_capture['started_at_utc'])<=parse_utc(run_capture['completed_at_utc'])<=workflow_completed or not workflow_started<=parse_utc(jobs_capture['started_at_utc'])<=parse_utc(jobs_capture['completed_at_utc'])<=workflow_completed or jobs_capture['tool_version']!=run_capture['tool_version']or gh_version is not None and run_capture['tool_version']!=gh_version:raise VerifyError('ACTIVATION_A03_RETAINED_WINDOW')
		gh_version=run_capture['tool_version'];run_document=load_json(run_payload,canonical=False,maximum=65536);jobs_document=load_json(jobs_payload,canonical=False,maximum=65536)
		if not isinstance(run_document,dict)or not isinstance(jobs_document,dict):raise VerifyError('ACTIVATION_A03_RAW_SHAPE')
		repository=run_document.get('repository')
		if run_document.get('id')!=run_id or run_document.get('run_attempt')!=run_attempt or run_document.get('url')!=api_root or run_document.get('html_url')!=run_url or run_document.get('path')!=workflow_path or run_document.get('event')!='push'or run_document.get('head_branch')!='main'or run_document.get('head_sha')!=qualification_commit or run_document.get('status')!='completed'or run_document.get('conclusion')!='success'or not isinstance(repository,dict)or repository.get('full_name')!='sepahead/haldir':raise VerifyError('ACTIVATION_A03_RAW_RUN')
		run_created=parse_utc(run_document.get('created_at'));run_updated=parse_utc(run_document.get('updated_at'))
		if not run_created<=run_updated<=parse_utc(run_capture['started_at_utc']):raise VerifyError('ACTIVATION_A03_RUN_TIME')
		raw_jobs=jobs_document.get('jobs')
		if jobs_document.get('total_count')!=len(job_names)or not isinstance(raw_jobs,list)or len(raw_jobs)!=len(job_names):raise VerifyError('ACTIVATION_A03_RAW_JOB_COUNT')
		raw_by_name:dict[str,dict[str,Any]]={}
		for raw_job in raw_jobs:
			if not isinstance(raw_job,dict):raise VerifyError('ACTIVATION_A03_RAW_JOB')
			name=raw_job.get('name')
			if name not in job_names or name in raw_by_name or raw_job.get('id')not in{item['job_id']for item in jobs}or raw_job.get('run_id')!=run_id or raw_job.get('run_attempt')!=run_attempt or raw_job.get('head_sha')!=qualification_commit or raw_job.get('status')!='completed'or raw_job.get('conclusion')!='success':raise VerifyError('ACTIVATION_A03_RAW_JOB_BINDING')
			job_started=parse_utc(raw_job.get('started_at'));job_completed=parse_utc(raw_job.get('completed_at'))
			if not run_created<=job_started<=job_completed<=run_updated:raise VerifyError('ACTIVATION_A03_RAW_JOB_TIME')
			raw_by_name[name]=raw_job
		if jobs!=[{'conclusion':'success','job_id':raw_by_name[name]['id'],'name':name}for name in job_names]:raise VerifyError('ACTIVATION_A03_JOB_PROJECTION')
		log_captures=workflow['job_log_captures']
		if not isinstance(log_captures,list)or len(log_captures)!=len(job_names)or[item.get('name')for item in log_captures]!=list(job_names):raise VerifyError('ACTIVATION_A03_JOB_LOG_SET')
		for(capture,job_name)in zip(log_captures,job_names,strict=True):
			capture=require_fields(capture,{'bytes','capture_argv','completed_at_utc','exit_code','job_id','kind','media_type','name','request_headers','retained_member','sha256','source_url','started_at_utc','stderr','stderr_sha256','tool_version'},'activation_a03_job_log');log_started=parse_utc(capture['started_at_utc']);log_completed=parse_utc(capture['completed_at_utc']);job_id=raw_by_name[job_name]['id'];api_path=f"repos/sepahead/haldir/actions/jobs/{job_id}/logs";source_url=f"https://api.github.com/{api_path}";argv=capture['capture_argv']
			if capture['job_id']!=job_id or capture['name']!=job_name or capture['retained_member']!=JOB_LOG_MEMBERS[job_name]or capture['kind']!='JOB_LOG_TEXT'or capture['media_type']!='text/plain'or capture['request_headers']!=['Accept: application/vnd.github+json','X-GitHub-Api-Version: 2022-11-28']or capture['source_url']!=source_url or type(capture['bytes'])is not int or not 0<capture['bytes']<=2097152 or re.fullmatch('[0-9a-f]{64}',capture['sha256'])is None or capture['exit_code']!=0 or capture['stderr']!=''or capture['stderr_sha256']!=sha256(b'')or capture['tool_version']!=gh_version or not workflow_started<=log_started<=log_completed<=workflow_completed or parse_utc(raw_by_name[job_name]['completed_at'])>log_started or not isinstance(argv,list)or not argv or not Path(argv[0]).is_absolute()or Path(argv[0]).name!='gh'or argv[1:]!=['api','--hostname','github.com','--method','GET','-H','Accept: application/vnd.github+json','-H','X-GitHub-Api-Version: 2022-11-28',api_path]:raise VerifyError('ACTIVATION_A03_JOB_LOG')
			all_log_captures.append(capture)
	if len(all_job_ids)!=len(ALL_HOSTED_JOB_NAMES):raise VerifyError('ACTIVATION_A03_JOB_CLOSURE')
	manifest=activation_log_manifest(archive_payload,all_log_captures);combined=require_fields(record['combined_log_archive'],{'artifact_evidence_id','completed_at_utc','entry_manifest','file','format','started_at_utc'},'activation_a03_combined_log_archive');archive_started=parse_utc(combined['started_at_utc']);archive_completed=parse_utc(combined['completed_at_utc'])
	if combined['artifact_evidence_id']!='CH-T003-A05'or combined['entry_manifest']!=manifest or combined['file']!=prospective_file_record(ACTIVATION_PATHS['CH-T003-A05'],archive_payload)or combined['format']!='ZIP_STORED_FLAT_EXACT_JOB_LOGS_V1'or combined['started_at_utc']!=min(item['started_at_utc']for item in all_log_captures)or combined['completed_at_utc']!=record['completed_at_utc']or not started<=archive_started<=archive_completed<=completed:raise VerifyError('ACTIVATION_A03_COMBINED_LOG')
	return started,completed,manifest
def validate_activation_a04(value:Any,*,freeze_commit:str,implementation_commit:str,qualification_commit:str,qualification_time:datetime,activation_time:datetime)->tuple[datetime,datetime]:
	record=require_fields(value,{'affected_downstreams','completed_at_utc','disposition','epoch','evidence_id','freeze_commit','implementation_commit','implementation_paths','qualification_commit','rationale','result','runtime_surface_changed','schema_id','started_at_utc','task_id'},'activation_a04');started=parse_utc(record['started_at_utc']);completed=parse_utc(record['completed_at_utc'])
	if record['schema_id']!='haldir.ch-t003.downstream-conformance-disposition.v1'or record['evidence_id']!='CH-T003-A04'or record['task_id']!=TASK_ID or record['epoch']!=EPOCH or record['freeze_commit']!=freeze_commit or record['implementation_commit']!=implementation_commit or record['qualification_commit']!=qualification_commit or record['result']!='PASS'or record['affected_downstreams']!=[]or record['implementation_paths']!=sorted(IMPLEMENTATION_PLAN)or record['runtime_surface_changed']is not False or record['disposition']!='NO_RUNTIME_OR_EXTERNAL_DOWNSTREAM_CONFORMANCE_CHANGE'or not isinstance(record['rationale'],str)or not record['rationale']or not qualification_time<=started<=completed<=activation_time:raise VerifyError('ACTIVATION_A04')
	return started,completed
def claim_inventory(payload:bytes)->list[dict[str,str]]:rows=parse_claim_rows(payload);return[{'id':item['id'],'status':item['status'],'statement_sha256':item['statement_sha256'],'support_sha256':item['evidence_sha256']}for item in rows]
def validate_activation_state_transition(*,repo:Path,freeze_commit:str,implementation_commit:str,qualification_commit:str,activation_commit:str,freeze:dict[str,Any],qualification:dict[str,Any],outcome:dict[str,Any],qualification_entries:list[dict[str,Any]],qualification_blobs:dict[str,bytes],activation_entries:list[dict[str,Any]],activation_blobs:dict[str,bytes])->tuple[dict[str,Any],dict[str,Any]]:
	prior_requirements=load_json(qualification_blobs[REQUIREMENTS_PATH],canonical=False);requirements=load_json(activation_blobs[REQUIREMENTS_PATH],canonical=False);expected_requirements=copy.deepcopy(prior_requirements);tasks=expected_requirements.get('tasks')
	if not isinstance(tasks,list)or len(tasks)!=126 or not isinstance(tasks[3],dict)or tasks[3].get('id')!=TASK_ID or tasks[3].get('status')!='OPEN':raise VerifyError('ACTIVATION_PRIOR_REQUIREMENTS')
	tasks[3].update({'status':'VERIFIED','claim_disposition':outcome['claim_disposition'],'assigned_reviewers':[item['id']for item in qualification['review_records']],'implementation_commits':[freeze_commit,implementation_commit],'evidence':[*[item['id']for item in qualification['evidence_records']],*[item['id']for item in freeze['activation_evidence_requirements']]],'closure_commit':qualification_commit,'twenty_lens_reviews':qualification['twenty_lens_reviews']});expected_requirements['overall_status']=outcome['overall_status']
	if requirements!=expected_requirements:raise VerifyError('ACTIVATION_REQUIREMENTS_TRANSITION')
	prior_claims=load_json(qualification_blobs[CLAIMS_STATE_PATH],canonical=False);claims=load_json(activation_blobs[CLAIMS_STATE_PATH],canonical=False);expected_claims=copy.deepcopy(prior_claims);inventory=claim_inventory(git_file(repo,implementation_commit,CLAIM_LEDGER_PATH));active_claims=outcome['active_claims'];expected_claims.update({'verified_prefix':4,'overall_status':outcome['overall_status'],'claim_inventory':inventory,'asserted_claims':[item for item in inventory if item['id']in active_claims],'active_claims':active_claims,'release_qualified_claims':outcome['release_qualified_claims'],'removed_claims':outcome['removed_claims'],'non_claimed_claims':outcome['non_claimed_claims'],'narrowed_claims':outcome['narrowed_claims'],'residual_limitations':qualification['limitations']});expected_claims['current_epochs']={**prior_claims['current_epochs'],TASK_ID:EPOCH};records={item['path']:copy.deepcopy(item)for item in prior_claims['public_surface_records']}
	for path in outcome['public_surfaces']:records[path]=exact_file_record(path,*tree_snapshot(repo,implementation_commit),include_selected_lines=True)
	claim_record=exact_file_record(CLAIM_LEDGER_PATH,*tree_snapshot(repo,implementation_commit),include_selected_lines=True);records[CLAIM_LEDGER_PATH]=claim_record;expected_claims['public_surface_records']=[records[path]for path in sorted(records)];expected_claims['claim_ledger']=claim_record;expected_claims.update({'tag_authorized':False,'github_release_authorized':False,'doi_authorized':False,'zenodo_authorized':False,'archive_authorized':False})
	if claims!=expected_claims:raise VerifyError('ACTIVATION_CLAIMS_TRANSITION')
	return requirements,claims
def validate_activation_stage(repo:Path,freeze_commit:str,implementation_commit:str,qualification_commit:str,activation_commit:str,qualification:dict[str,Any])->None:
	freeze_entries,freeze_blobs=tree_snapshot(repo,freeze_commit);qualification_entries,qualification_blobs=tree_snapshot(repo,qualification_commit);activation_entries,activation_blobs=tree_snapshot(repo,activation_commit);freeze=load_json(freeze_blobs[FREEZE_PATH],canonical=False)
	if not isinstance(freeze,dict):raise VerifyError('ACTIVATION_FREEZE')
	outcomes=freeze.get('claim_outcomes')
	if not isinstance(outcomes,list)or len(outcomes)!=1:raise VerifyError('ACTIVATION_OUTCOME')
	outcome=outcomes[0];qualification_time=commit_time(repo,qualification_commit);activation_time=commit_time(repo,activation_commit);documents={identifier:load_json(activation_blobs[path])if identifier!='CH-T003-A05'else activation_blobs[path]for(identifier,path)in ACTIVATION_PATHS.items()};a01_times=validate_activation_a01(documents['CH-T003-A01'],freeze_commit=freeze_commit,implementation_commit=implementation_commit,qualification_commit=qualification_commit,qualification_time=qualification_time,activation_time=activation_time);a02_times=validate_activation_a02(documents['CH-T003-A02'],freeze_commit=freeze_commit,implementation_commit=implementation_commit,qualification_commit=qualification_commit,qualification_time=qualification_time,activation_time=activation_time);a03_started,a03_completed,_manifest=validate_activation_a03(documents['CH-T003-A03'],archive_payload=documents['CH-T003-A05'],freeze_commit=freeze_commit,implementation_commit=implementation_commit,qualification_commit=qualification_commit,qualification_time=qualification_time,activation_time=activation_time);a04_times=validate_activation_a04(documents['CH-T003-A04'],freeze_commit=freeze_commit,implementation_commit=implementation_commit,qualification_commit=qualification_commit,qualification_time=qualification_time,activation_time=activation_time);a05_log=documents['CH-T003-A03']['combined_log_archive'];evidence_times={'CH-T003-A01':a01_times,'CH-T003-A02':a02_times,'CH-T003-A03':(a03_started,a03_completed),'CH-T003-A04':a04_times,'CH-T003-A05':(parse_utc(a05_log['started_at_utc']),parse_utc(a05_log['completed_at_utc']))};registry=load_json(freeze_blobs[REGISTRY_PATH],canonical=False);registrations=registry.get('registrations')if isinstance(registry,dict)else None;selected=[item for item in registrations or[]if isinstance(item,dict)and item.get('task_id')==TASK_ID and item.get('epoch')==EPOCH]
	if len(selected)!=1:raise VerifyError('ACTIVATION_REGISTRATION')
	registration=selected[0];receipt=require_fields(load_json(activation_blobs[RECEIPT_PATH]),{'schema_version','task_id','epoch','freeze_commit','implementation_commit','qualification_commit','verifier_sha256','tests_sha256','selected_claim_outcome_id','result','runtime_target_policy'},'activation_receipt')
	if receipt!={'schema_version':'1.0.0','task_id':TASK_ID,'epoch':EPOCH,'freeze_commit':freeze_commit,'implementation_commit':implementation_commit,'qualification_commit':qualification_commit,'verifier_sha256':registration['verifier']['sha256'],'tests_sha256':registration['tests']['sha256'],'selected_claim_outcome_id':OUTCOME_ID,'result':'PASS','runtime_target_policy':'CENTRAL_VERIFIER_EXECUTES_EXACT_F_BLOBS_AT_D_AND_FROZEN_TRIGGERED_CHANGES'}:raise VerifyError('ACTIVATION_RECEIPT')
	requirements,claims=validate_activation_state_transition(repo=repo,freeze_commit=freeze_commit,implementation_commit=implementation_commit,qualification_commit=qualification_commit,activation_commit=activation_commit,freeze=freeze,qualification=qualification,outcome=outcome,qualification_entries=qualification_entries,qualification_blobs=qualification_blobs,activation_entries=activation_entries,activation_blobs=activation_blobs);activation=require_fields(load_json(activation_blobs[ACTIVATION_PATH]),ACTIVATION_FIELDS,'activation');evidence_records:list[dict[str,Any]]=[]
	for(identifier,kind,_name,_schema)in ACTIVATION_SPECS:
		path=ACTIVATION_PATHS[identifier];payload=activation_blobs[path];started,completed=evidence_times[identifier];evidence_records.append({'completed_at_utc':completed.strftime('%Y-%m-%dT%H:%M:%SZ'),'file':exact_file_record(path,activation_entries,activation_blobs,include_selected_lines=True),'id':identifier,'kind':kind,'result':'PASS','started_at_utc':started.strftime('%Y-%m-%dT%H:%M:%SZ'),'subject_commit':qualification_commit});maximum=2097152 if identifier=='CH-T003-A05'else 4194304
		if len(payload)>maximum:raise VerifyError('ACTIVATION_EVIDENCE_BOUND')
	for item in activation['activation_evidence_records']:require_fields(item,ACTIVATION_EVIDENCE_RECORD_FIELDS,'activation_evidence_record')
	expected_decision={'task_status':'VERIFIED','claim_disposition':outcome['claim_disposition'],'overall_status':outcome['overall_status'],'tag_authorized':False,'github_release_authorized':False,'doi_authorized':False,'zenodo_authorized':False,'archive_authorized':False}
	if activation['schema_version']!='1.0.0'or activation['task_id']!=TASK_ID or activation['epoch']!=EPOCH or activation['release_target']!=RELEASE_TARGET or activation['author']!=AUTHOR or activation['persistent_identifier']is not None or activation['effective_on']!='SIGNED_COMMIT_FIRST_CONTAINING_EXACT_ACTIVATION_RECEIPTS_AND_TRANSITION'or activation['freeze_commit']!=freeze_commit or activation['implementation_commit']!=implementation_commit or activation['qualification_commit']!=qualification_commit or activation['qualification_record']!=exact_file_record(QUALIFICATION_PATH,qualification_entries,qualification_blobs,include_selected_lines=True)or activation['verifier_receipt']!=exact_file_record(RECEIPT_PATH,activation_entries,activation_blobs,include_selected_lines=True)or activation['activation_evidence_records']!=evidence_records or activation['requirements_record']!=exact_file_record(REQUIREMENTS_PATH,activation_entries,activation_blobs,include_selected_lines=True)or activation['active_claims_record']!=exact_file_record(CLAIMS_STATE_PATH,activation_entries,activation_blobs,include_selected_lines=True)or activation['selected_claim_outcome']!=outcome or activation['decision']!=expected_decision or requirements.get('overall_status')!='NO_GO'or claims.get('overall_status')!='NO_GO':raise VerifyError('ACTIVATION_RECORD')
def validate_freeze_contract(repo:Path,freeze_commit:str,freeze:dict[str,Any],freeze_entries:list[dict[str,Any]],freeze_blobs:dict[str,bytes])->None:
	fields={'schema_version','task_id','epoch','release_target','author','persistent_identifier','effective_on','task_identity','handoff_task_contract','prior_state','implementation_plan','empty_implementation_reason','affected_surface_inventory','normative_controls','lead_approval','mandatory_counterfactuals','combined_attack_matrix','handoff_command_mapping','threat_model','misuse_resistant_interfaces','qualification_evidence_requirements','review_requirements','reviewer_registry','activation_evidence_requirements','lens_questions','resource_budgets','verification_triggers','claim_outcomes','qualification_path','activation_path','verifier_receipt_path'};require_fields(freeze,fields,'freeze_contract')
	if freeze['schema_version']!='1.0.0'or freeze['task_id']!=TASK_ID or freeze['epoch']!=EPOCH or freeze['release_target']!=RELEASE_TARGET or freeze['author']!=AUTHOR or freeze['persistent_identifier']is not None or freeze['effective_on']!='SIGNED_COMMIT_FIRST_CONTAINING_EXACT_FREEZE_AND_REGISTRATION'or freeze['implementation_plan']!=IMPLEMENTATION_PLAN or freeze['empty_implementation_reason']is not None or freeze['qualification_path']!=QUALIFICATION_PATH or freeze['activation_path']!=ACTIVATION_PATH or freeze['verifier_receipt_path']!=RECEIPT_PATH:raise VerifyError('FREEZE_IDENTITY')
	prior_entries,prior_blobs=tree_snapshot(repo,PRIOR_ACTIVATION);prior_requirements=load_json(prior_blobs[REQUIREMENTS_PATH],canonical=False);tasks=prior_requirements.get('tasks')if isinstance(prior_requirements,dict)else None
	if not isinstance(tasks,list)or len(tasks)!=126 or not isinstance(tasks[3],dict)or tasks[3].get('id')!=TASK_ID:raise VerifyError('FREEZE_PRIOR_TASK')
	task=tasks[3];identity_fields='id','source_task_id','source_record_sha256','phase','title','source_scope','focus','priority','dependencies','execution_wave','subagent_lane','lead_review_required'
	if freeze['task_identity']!={field:task[field]for field in identity_fields}:raise VerifyError('FREEZE_TASK_IDENTITY')
	prior_freeze=load_json(prior_blobs['release/0.9.0/current-head/tasks/ch-t002/e0002/freeze.json'],canonical=False)
	if not isinstance(prior_freeze,dict):raise VerifyError('FREEZE_PRIOR_CONTRACT')
	expected_handoff=copy.deepcopy(prior_freeze['handoff_task_contract']);expected_handoff.update({'source_task_id':task['source_task_id'],'source_record_sha256':task['source_record_sha256'],'lead_review_required':task['lead_review_required'],'bootstrap_amendment':{'exception':None,'postconditions':['COMPLETE_CH-T001_INVENTORY_RETAINED','COMPLETE_CH-T002_ASSIGNMENTS_AND_REVIEWS_RETAINED']}})
	if freeze['handoff_task_contract']!=expected_handoff:raise VerifyError('FREEZE_HANDOFF_CONTRACT')
	prior_claims_payload=prior_blobs[CLAIMS_STATE_PATH]
	if freeze['prior_state']!={'verified_prefix':3,'active_claims':{'path':CLAIMS_STATE_PATH,'sha256':sha256(prior_claims_payload),'bytes':len(prior_claims_payload),'lines':len(prior_claims_payload.splitlines())}}:raise VerifyError('FREEZE_PRIOR_STATE')
	affected=freeze['affected_surface_inventory']
	if not isinstance(affected,list)or len(affected)!=9 or[item.get('path')for item in affected]!=list(IMPLEMENTATION_PLAN):raise VerifyError('FREEZE_AFFECTED_SURFACES')
	expected_classifications={path:'PUBLIC_DOCUMENTATION'if path.startswith('docs/')else'TEST_OR_TOOLING'if path.startswith('tools/')else'INTERNAL_IMPLEMENTATION'for path in IMPLEMENTATION_PLAN}
	for item in affected:
		item=require_fields(item,{'path','planned_status','classification','claim_relevance','in_repository_consumers','external_consumers','rationale'},'freeze_affected_surface');path=item['path']
		if item['planned_status']!=IMPLEMENTATION_PLAN[path]or item['classification']!=expected_classifications[path]or item['claim_relevance']!=('PUBLIC_CLAIM_REVIEW_REQUIRED'if path==CLAIM_LEDGER_PATH else'SEMANTIC_REVIEW_REQUIRED')or not isinstance(item['in_repository_consumers'],list)or not item['in_repository_consumers']or not all(isinstance(value,str)and valid_path(value)for value in item['in_repository_consumers'])or item['external_consumers']!=(['Repository readers and downstream documentation tooling']if path==CLAIM_LEDGER_PATH else[])or not isinstance(item['rationale'],str)or not item['rationale']:raise VerifyError('FREEZE_AFFECTED_SURFACE_BINDING')
	requirement_ids,counterfactual_ids,test_ids,_test_order=freeze_control_sets(freeze);test_source=freeze_blobs[TESTS_PATH].decode('utf-8')
	for control in freeze['normative_controls']:
		if' SHALL 'not in f" {control["statement"]} "or f"def {control["accepted_test_id"]}("not in test_source or f"def {control["rejected_test_id"]}("not in test_source:raise VerifyError('FREEZE_CONTROL_TEST_BINDING')
	prior_counterfactuals=expected_handoff['mandatory_counterfactuals']
	if[item['statement']for item in freeze['mandatory_counterfactuals']]!=prior_counterfactuals:raise VerifyError('FREEZE_COUNTERFACTUAL_STATEMENTS')
	for item in freeze['mandatory_counterfactuals']:
		if f"def {item["accepted_test_id"]}("not in test_source or f"def {item["rejected_test_id"]}("not in test_source:raise VerifyError('FREEZE_COUNTERFACTUAL_TEST_BINDING')
	evidence_requirements=[{'id':identifier,'kind':kind,'path':EVIDENCE_PATHS[identifier],'max_bytes':4194304}for(identifier,kind,_name,_schema)in EVIDENCE_SPECS];review_requirements=[{'id':identifier,'kind':kind,'path':REVIEW_PATHS[identifier],'max_bytes':4194304}for(identifier,kind,_name)in REVIEW_SPECS];activation_requirements=[{'id':identifier,'kind':kind,'path':ACTIVATION_PATHS[identifier],'max_bytes':2097152 if identifier=='CH-T003-A05'else 4194304}for(identifier,kind,_name,_schema)in ACTIVATION_SPECS]
	if freeze['qualification_evidence_requirements']!=evidence_requirements or freeze['review_requirements']!=review_requirements or freeze['activation_evidence_requirements']!=activation_requirements:raise VerifyError('FREEZE_EVIDENCE_REQUIREMENTS')
	frozen_reviewers=reviewer_registry(freeze)
	for(identifier,requirement)in zip(frozen_reviewers,review_requirements,strict=True):
		reviewer=frozen_reviewers[identifier]
		if reviewer['kind']!=requirement['kind']or reviewer['path']!=requirement['path']:raise VerifyError('FREEZE_REVIEWER_REQUIREMENT')
	if freeze['lens_questions']!=prior_freeze['lens_questions']:raise VerifyError('FREEZE_LENSES')
	if freeze['resource_budgets']!={'json_bytes':262144,'decompressed_evidence_bytes':4194304,'protocol_path_bytes':240,'verifier_output_bytes_per_stream':65536,'verifier_seconds':10}or freeze['verification_triggers']!={'paths':list(IMPLEMENTATION_PLAN),'roots':[]}:raise VerifyError('FREEZE_RESOURCE_OR_TRIGGER')
	combined=freeze['combined_attack_matrix']
	if not isinstance(combined,list)or not combined:raise VerifyError('FREEZE_COMBINED_MATRIX')
	for(index,item)in enumerate(combined,1):
		item=require_fields(item,{'id','statement','disposition','rationale','falsifier','control_ids','evidence_ids','accepted_test_id','rejected_test_id'},'freeze_combined_attack');applicable=item['disposition']=='APPLICABLE'
		if item['id']!=f"CH-T003-CA{index:02d}"or item['disposition']not in{'APPLICABLE','NOT_APPLICABLE'}or not isinstance(item['statement'],str)or not item['statement']or not isinstance(item['rationale'],str)or not item['rationale']or not set(item['control_ids']).issubset(requirement_ids)or not set(item['evidence_ids']).issubset({entry[0]for entry in EVIDENCE_SPECS})or applicable and(item['falsifier']is not None or item['accepted_test_id']not in test_ids or item['rejected_test_id']not in test_ids)or not applicable and(not isinstance(item['falsifier'],str)or not item['falsifier']or item['accepted_test_id']is not None or item['rejected_test_id']is not None):raise VerifyError('FREEZE_COMBINED_ATTACK_BINDING')
	command_mapping=freeze['handoff_command_mapping']
	if not isinstance(command_mapping,list)or[item.get('id')for item in command_mapping]!=['HC01','HC02','HC03','HC04']or command_mapping[-1].get('disposition')!='SUPERSEDED_BY_STRONGER_BOUND_EQUIVALENT'or not isinstance(command_mapping[-1].get('replacement_commands'),list)or len(command_mapping[-1]['replacement_commands'])!=4 or not all(isinstance(item,str)and item for item in command_mapping[-1]['replacement_commands']):raise VerifyError('FREEZE_COMMAND_MAPPING')
	threats=freeze['threat_model']
	if not isinstance(threats,list)or len(threats)!=6 or[item.get('threat_id')for item in threats]!=[f"CH-T003-TH{index:02d}"for index in range(1,7)]:raise VerifyError('FREEZE_THREAT_MODEL')
	threat_fields={'threat_id','asset_or_claim','actor','preconditions','sequence','trust_boundary','observable_symptoms','worst_consequence','preventive_controls','detective_controls','recovery','tests','evidence','residual_risk','claim_impact','owner'}
	for item in threats:
		require_fields(item,threat_fields,'freeze_threat')
		if item['owner']!=TASK_ID or not set(item['preventive_controls']).issubset(requirement_ids)or not set(item['detective_controls']).issubset(requirement_ids)or not set(item['tests']).issubset(test_ids)or not set(item['evidence']).issubset({entry[0]for entry in EVIDENCE_SPECS}):raise VerifyError('FREEZE_THREAT_BINDING')
	misuse=freeze['misuse_resistant_interfaces']
	if not isinstance(misuse,list)or len(misuse)!=4 or{item.get('id')for item in misuse}!={f"CH-T003-MI{index:02d}"for index in range(1,5)}:raise VerifyError('FREEZE_MISUSE_MODEL')
	misuse_fields={'id','surface','disposition','justification','falsifier','correct_example','wrong_example','exact_refusal_or_error','non_proofs','evidence_tier','evidence_ids','invariant_ids','test_ids'}
	for item in misuse:
		require_fields(item,misuse_fields,'freeze_misuse')
		if item['disposition']!='APPLICABLE'or item['falsifier']is not None or not set(item['evidence_ids']).issubset({entry[0]for entry in EVIDENCE_SPECS})or not set(item['invariant_ids']).issubset(requirement_ids)or not set(item['test_ids']).issubset(test_ids)or not isinstance(item['non_proofs'],list)or not item['non_proofs']:raise VerifyError('FREEZE_MISUSE_BINDING')
	prior_claims=load_json(prior_claims_payload,canonical=False);outcomes=freeze['claim_outcomes']
	if not isinstance(outcomes,list)or len(outcomes)!=1:raise VerifyError('FREEZE_OUTCOMES')
	outcome=require_fields(outcomes[0],{'id','claim_disposition','overall_status','active_claims','release_qualified_claims','removed_claims','non_claimed_claims','narrowed_claims','limitations','public_surfaces','migration','rollback'},'freeze_outcome');expected_narrowed=sorted(set(prior_claims['narrowed_claims'])|{NARROWED_CLAIM})
	if outcome['id']!=OUTCOME_ID or outcome['claim_disposition']!='PUBLIC_CLAIMS_NARROWED'or outcome['overall_status']!='NO_GO'or outcome['active_claims']!=prior_claims['active_claims']or outcome['release_qualified_claims']!=prior_claims['release_qualified_claims']or outcome['release_qualified_claims']!=[]or outcome['removed_claims']!=prior_claims['removed_claims']or outcome['non_claimed_claims']!=prior_claims['non_claimed_claims']or outcome['narrowed_claims']!=expected_narrowed or outcome['public_surfaces']!=[CLAIM_LEDGER_PATH]or not isinstance(outcome['limitations'],list)or outcome['limitations']!=sorted(set(outcome['limitations']))or len(outcome['limitations'])!=6 or outcome['migration']!={'required':True,'paths':list(IMPLEMENTATION_PLAN),'disposition':'ADD_EXACT_PUBLIC_SURFACE_AND_CLAIM_TIER_RECORDS_AND_NARROW_ONE_AMBIGUOUS_CLAIM_ROW'}or outcome['rollback']!={'strategy':'RESTORE_EXACT_PRIOR_ACTIVATED_TREE_ENTRIES','paths':list(IMPLEMENTATION_PLAN),'verification':'GIT_MODE_TYPE_AND_OBJECT_IDENTITY'}:raise VerifyError('FREEZE_OUTCOME_BINDING')
	authority_text=canonical_json(outcome).decode('utf-8')
	for required in('No release, deployment, publication, tag, GitHub release, DOI, Zenodo record, or archive authority is granted.','VALIDATED','DEPLOYMENT_QUALIFIED','FIELD_VALIDATED'):
		if required not in authority_text:raise VerifyError('FREEZE_OUTCOME_LIMITATION')
	approval=require_fields(freeze['lead_approval'],{'kind','human','external_authority','freeze_packet_sha256','effective_on'},'freeze_approval');digest_source={key:freeze[key]for key in sorted(freeze)if key!='lead_approval'}
	if approval!={'kind':'AUTOMATED_NON_HUMAN_LEAD_SUPPORT','human':False,'external_authority':False,'freeze_packet_sha256':sha256(json.dumps(digest_source,sort_keys=True,separators=(',',':')).encode('utf-8')),'effective_on':'SIGNED_F_COMMIT_CONTAINING_EXACT_PREIMPLEMENTATION_PACKET'}:raise VerifyError('FREEZE_APPROVAL')
	registry=load_json(freeze_blobs[REGISTRY_PATH],canonical=False);prior_registry=load_json(prior_blobs[REGISTRY_PATH],canonical=False)
	if not isinstance(registry,dict)or not isinstance(prior_registry,dict)or set(registry)!=set(prior_registry)or{key:registry[key]for key in registry if key!='registrations'}!={key:prior_registry[key]for key in prior_registry if key!='registrations'}or not isinstance(registry.get('registrations'),list)or registry['registrations'][:-1]!=prior_registry.get('registrations'):raise VerifyError('FREEZE_REGISTRY_PREFIX')
	registration=require_fields(registry['registrations'][-1],{'task_id','epoch','verifier','tests','freeze_contract','qualification_path','activation_path','verifier_receipt_path','effective_on'},'freeze_registration')
	if registration!={'task_id':TASK_ID,'epoch':EPOCH,'verifier':protocol_file_record(VERIFIER_PATH,freeze_entries,freeze_blobs),'tests':protocol_file_record(TESTS_PATH,freeze_entries,freeze_blobs),'freeze_contract':protocol_file_record(FREEZE_PATH,freeze_entries,freeze_blobs),'qualification_path':QUALIFICATION_PATH,'activation_path':ACTIVATION_PATH,'verifier_receipt_path':RECEIPT_PATH,'effective_on':'SIGNED_COMMIT_FIRST_CONTAINING_EXACT_REGISTRATION_FREEZE_AND_GATES'}:raise VerifyError('FREEZE_REGISTRATION')
def validate_implementation(repo:Path,freeze_commit:str,implementation_commit:str)->None:
	commits={'F':freeze_commit,'I':implementation_commit};metas={stage:commit_meta(repo,commit)for(stage,commit)in commits.items()}
	if metas['F']['parents']!=PRIOR_ACTIVATION or metas['I']['parents']!=freeze_commit:raise VerifyError('IMPLEMENTATION_ADJACENCY')
	for(stage,commit)in commits.items():
		if metas[stage]['subject']!=EXPECTED_SUBJECTS[stage]or metas[stage]['author_name']!=AUTHOR['name']or metas[stage]['author_email']!=AUTHOR['email']:raise VerifyError('COMMIT_IDENTITY')
		verify_signature(repo,commit)
	if changed_statuses(repo,PRIOR_ACTIVATION,freeze_commit)!={REGISTRY_PATH:'M',FREEZE_PATH:'A',TESTS_PATH:'A',VERIFIER_PATH:'A'}:raise VerifyError('FREEZE_DIFF')
	if changed_statuses(repo,freeze_commit,implementation_commit)!=IMPLEMENTATION_PLAN:raise VerifyError('IMPLEMENTATION_DIFF')
	freeze_entries,freeze_blobs=tree_snapshot(repo,freeze_commit);freeze=load_json(freeze_blobs[FREEZE_PATH],canonical=False)
	if not isinstance(freeze,dict):raise VerifyError('FREEZE_IDENTITY')
	validate_freeze_contract(repo,freeze_commit,freeze,freeze_entries,freeze_blobs);validate_products(repo,freeze_commit,implementation_commit)
def validate_current_state(repo:Path,implementation_commit:str,current_commit:str)->None:
	immutable_paths=set(IMPLEMENTATION_PLAN)-{CLAIM_LEDGER_PATH}
	for path in sorted(immutable_paths):
		implementation_entry=targeted_tree_entry(repo,implementation_commit,path);current_entry=targeted_tree_entry(repo,current_commit,path);identity_fields='git_mode','git_object_type','git_object_id'
		if any(implementation_entry[field]!=current_entry[field]for field in identity_fields):raise VerifyError('CURRENT_IMPLEMENTATION_SURFACE_DRIFT')
	implementation_ledger_entry=targeted_tree_entry(repo,implementation_commit,CLAIM_LEDGER_PATH);current_ledger_entry=targeted_tree_entry(repo,current_commit,CLAIM_LEDGER_PATH)
	if implementation_ledger_entry['git_mode']!=current_ledger_entry['git_mode']or implementation_ledger_entry['git_object_type']!=current_ledger_entry['git_object_type']:raise VerifyError('CURRENT_NARROWED_CLAIM_DRIFT')
	implementation_rows=parse_claim_rows(git_file(repo,implementation_commit,CLAIM_LEDGER_PATH,maximum=MAX_BLOB_BYTES));current_rows=parse_claim_rows(git_file(repo,current_commit,CLAIM_LEDGER_PATH,maximum=MAX_BLOB_BYTES));implementation_target=next((item for item in implementation_rows if item['id']==NARROWED_CLAIM),None);current_target=next((item for item in current_rows if item['id']==NARROWED_CLAIM),None)
	if implementation_target is None or current_target!=implementation_target:raise VerifyError('CURRENT_NARROWED_CLAIM_DRIFT')
def validate_lifecycle(repo:Path,freeze_commit:str,implementation_commit:str,qualification_commit:str,activation_commit:str,current_commit:str)->dict[str,Any]:
	validate_implementation(repo,freeze_commit,implementation_commit);commits={'F':freeze_commit,'I':implementation_commit,'C':qualification_commit,'D':activation_commit};metas={stage:commit_meta(repo,commit)for(stage,commit)in commits.items()}
	if metas['F']['parents']!=PRIOR_ACTIVATION or metas['I']['parents']!=freeze_commit or metas['C']['parents']!=implementation_commit or metas['D']['parents']!=qualification_commit:raise VerifyError('LIFECYCLE_ADJACENCY')
	if not is_ancestor(repo,activation_commit,current_commit):raise VerifyError('CURRENT_NOT_DESCENDANT')
	for stage in('C','D'):
		commit=commits[stage]
		if metas[stage]['subject']!=EXPECTED_SUBJECTS[stage]or metas[stage]['author_name']!=AUTHOR['name']or metas[stage]['author_email']!=AUTHOR['email']:raise VerifyError('COMMIT_IDENTITY')
		verify_signature(repo,commit)
	expected_c_diff={QUALIFICATION_PATH:'A',**{path:'A'for path in EVIDENCE_PATHS.values()},**{path:'A'for path in REVIEW_PATHS.values()}};expected_d_diff={ACTIVATION_PATH:'A',RECEIPT_PATH:'A',REQUIREMENTS_PATH:'M',CLAIMS_STATE_PATH:'M',**{path:'A'for path in ACTIVATION_PATHS.values()}}
	if changed_statuses(repo,implementation_commit,qualification_commit)!=dict(sorted(expected_c_diff.items())):raise VerifyError('QUALIFICATION_DIFF')
	if changed_statuses(repo,qualification_commit,activation_commit)!=dict(sorted(expected_d_diff.items())):raise VerifyError('ACTIVATION_DIFF')
	qualification=validate_qualification_stage(repo,freeze_commit,implementation_commit,qualification_commit);validate_activation_stage(repo,freeze_commit,implementation_commit,qualification_commit,activation_commit,qualification);validate_current_state(repo,implementation_commit,current_commit);requirements=load_json(git_file(repo,activation_commit,REQUIREMENTS_PATH),canonical=False);claims=load_json(git_file(repo,activation_commit,CLAIMS_STATE_PATH),canonical=False);task=requirements.get('tasks',[None]*4)[3]
	if not isinstance(task,dict)or task.get('id')!=TASK_ID or task.get('status')!='VERIFIED'or requirements.get('overall_status')!='NO_GO':raise VerifyError('REQUIREMENTS_STATE')
	if claims.get('verified_prefix')!=4 or claims.get('current_epochs',{}).get(TASK_ID)!=EPOCH or claims.get('overall_status')!='NO_GO'or NARROWED_CLAIM not in claims.get('narrowed_claims',[])or claims.get('release_qualified_claims')!=[]or any(claims.get(field)is not False for field in('tag_authorized','github_release_authorized','doi_authorized','zenodo_authorized','archive_authorized')):raise VerifyError('CLAIMS_STATE')
	return qualification
def implementation_output_record(repo:Path,freeze_commit:str,implementation_commit:str)->dict[str,Any]:return{'schema_version':'1.0.0','task_id':TASK_ID,'epoch':EPOCH,'freeze_commit':freeze_commit,'implementation_commit':implementation_commit,'verifier_sha256':sha256(git_file(repo,freeze_commit,VERIFIER_PATH)),'tests_sha256':sha256(git_file(repo,freeze_commit,TESTS_PATH)),'mode':'IMPLEMENTATION_ONLY','result':'PASS'}
def output_record(repo:Path,freeze_commit:str,implementation_commit:str,qualification_commit:str,activation_commit:str,current_commit:str,qualification:dict[str,Any])->dict[str,Any]:return{'schema_version':'1.0.0','task_id':TASK_ID,'epoch':EPOCH,'freeze_commit':freeze_commit,'implementation_commit':implementation_commit,'qualification_commit':qualification_commit,'activation_commit':activation_commit,'current_commit':current_commit,'verifier_sha256':sha256(git_file(repo,freeze_commit,VERIFIER_PATH)),'tests_sha256':sha256(git_file(repo,freeze_commit,TESTS_PATH)),'selected_claim_outcome_id':qualification['selected_claim_outcome_id'],'result':'PASS'}
def parser()->argparse.ArgumentParser:value=argparse.ArgumentParser();value.add_argument('--repo',required=True);value.add_argument('--freeze-commit',required=True);value.add_argument('--implementation-commit',required=True);value.add_argument('--qualification-commit');value.add_argument('--activation-commit');value.add_argument('--current-commit');value.add_argument('--implementation-only',action='store_true');return value
def main()->int:
	arguments=parser().parse_args()
	try:
		repo=Path(arguments.repo).resolve(strict=True);lifecycle_values=arguments.qualification_commit,arguments.activation_commit,arguments.current_commit
		if arguments.implementation_only:
			if any(item is not None for item in lifecycle_values):raise VerifyError('IMPLEMENTATION_ONLY_ARGUMENTS')
			validate_implementation(repo,arguments.freeze_commit,arguments.implementation_commit);result=implementation_output_record(repo,arguments.freeze_commit,arguments.implementation_commit)
		else:
			if any(item is None for item in lifecycle_values):raise VerifyError('LIFECYCLE_ARGUMENTS')
			qualification=validate_lifecycle(repo,arguments.freeze_commit,arguments.implementation_commit,arguments.qualification_commit,arguments.activation_commit,arguments.current_commit);result=output_record(repo,arguments.freeze_commit,arguments.implementation_commit,arguments.qualification_commit,arguments.activation_commit,arguments.current_commit,qualification)
	except(OSError,UnicodeError,VerifyError,ValueError,TypeError)as error:sys.stderr.write(f"verify-ch-t003: {error}\n");return 1
	sys.stdout.buffer.write(canonical_json(result));return 0
if __name__=='__main__':raise SystemExit(main())
