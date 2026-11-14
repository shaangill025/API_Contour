"""Pure private input/exec controls; execve and fd0 replacement are mocked."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('input_adapter',Path(__file__).with_name('exec_input.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class InputTests(unittest.TestCase):
 def test_private_file_identity_and_negative_cases(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
   parent=Path(tmp);parent.chmod(0o700);p=parent/'input';p.write_bytes(b'synthetic');p.chmod(0o600);digest=hashlib.sha256(b'synthetic').hexdigest()
   fd=m.checked_file(p,digest,0o600,65536)
   try:self.assertEqual(os.read(fd,9),b'synthetic')
   finally:os.close(fd)
   with self.assertRaises(ValueError):m.checked_file(p,'0'*64,0o600,65536)
   p.chmod(0o644)
   with self.assertRaises(ValueError):m.checked_file(p,digest,0o600,65536)
   p.chmod(0o600)
   replacement=parent/'replacement';replacement.write_bytes(b'synthetic');replacement.chmod(0o600);real_read=os.read;swapped=[False]
   def raced(fd,n):
    value=real_read(fd,n)
    if not swapped[0]:swapped[0]=True;os.replace(replacement,p)
    return value
   with patch.object(m.os,'read',side_effect=raced):
    with self.assertRaises(ValueError):m.checked_file(p,digest,0o600,65536)
   os.link(p,parent/'link')
   with self.assertRaises(ValueError):m.checked_file(p,digest,0o600,65536)
   (parent/'link').unlink();p.unlink();p.symlink_to(parent/'missing')
   with self.assertRaises(OSError):m.checked_file(p,digest,0o600,65536)
   p.unlink();os.mkfifo(p,0o600)
   with self.assertRaises(ValueError):m.checked_file(p,digest,0o600,65536)
 def test_exact_exec_arguments_and_no_secret_in_environment(self):
  with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
   root=Path(tmp);root.chmod(0o700);config=root/'config';config.mkdir(mode=0o700);payload=root/'input';payload.write_bytes(b'R5I1'+len(b'synthetic-private').to_bytes(4,'big')+b'synthetic-private');payload.chmod(0o600);tool=root/'tool';tool.write_bytes(b'executable');tool.chmod(0o500)
   digest=hashlib.sha256(payload.read_bytes()).hexdigest();toolhash=hashlib.sha256(tool.read_bytes()).hexdigest()
   with patch.dict(os.environ,{'DOCKER_CONTEXT':'foreign','DOCKER_API_VERSION':'1.1','LD_PRELOAD':'foreign','HTTPS_PROXY':'foreign'}),patch.object(m,'DOCKER',str(tool)),patch.object(m,'DOCKER_SHA',toolhash),patch.object(m,'socket_snapshot',return_value='e'*64),patch.object(m.os,'closerange') as closefds,patch.object(m.os,'dup2') as dup,patch.object(m.os,'execve',side_effect=RuntimeError('intercept')) as execute:
    with self.assertRaises(RuntimeError):m.launch(payload,digest,config,'a'*64,'e'*64)
    dup.assert_called_once();closefds.assert_called_once();args=execute.call_args.args;self.assertEqual(args[0],str(tool));self.assertEqual(args[1][-4:],['start','--attach','--interactive','a'*64]);self.assertNotIn('synthetic-private',repr(args));self.assertTrue(all(key not in args[2] for key in ('DOCKER_CONTEXT','DOCKER_API_VERSION','LD_PRELOAD','HTTPS_PROXY')))
   (config/'unexpected').write_text('x')
   with patch.object(m,'socket_snapshot',return_value='e'*64),patch.object(m.os,'dup2') as dup,patch.object(m.os,'execve') as execute:
    with self.assertRaises(ValueError):m.launch(payload,digest,config,'a'*64,'e'*64)
    dup.assert_not_called();execute.assert_not_called()
 def test_original_socket_digest_required_before_exec(self):
  with patch.object(m,'socket_snapshot',return_value='f'*64),patch.object(m.os,'dup2') as dup,patch.object(m.os,'execve') as execute:
   with self.assertRaises(ValueError):m.launch('/x','a'*64,'/x','b'*64,'e'*64)
   dup.assert_not_called();execute.assert_not_called()
 def test_invalid_cid_or_digest_never_executes(self):
  with patch.object(m.os,'dup2') as dup,patch.object(m.os,'execve') as execute:
   for digest,cid in [('bad','a'*64),('a'*64,'bad')]:
    with self.assertRaises(ValueError):m.launch('/x',digest,'/x',cid,'e'*64)
   dup.assert_not_called();execute.assert_not_called()
if __name__=='__main__':unittest.main()
