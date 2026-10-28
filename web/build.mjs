import {createRequire} from 'node:module';
import {access} from 'node:fs/promises';
const require = createRequire(import.meta.url);
// Use only npm's locked platform package. Do not execute esbuild's installer or
// permit its fallback download path. Missing platform packages fail the build.
const platformPackage = `@esbuild/${process.platform}-${process.arch}`;
const binary = require.resolve(`${platformPackage}/${process.platform === 'win32' ? 'esbuild.exe' : 'bin/esbuild'}`);
await access(binary);
process.env.ESBUILD_BINARY_PATH = binary;
const {build} = await import('esbuild');
import {mkdir, copyFile} from 'node:fs/promises';
await mkdir('dist/assets', {recursive: true});
await build({
  entryPoints: ['src/main.tsx'], bundle: true, minify: true, format: 'esm',
  target: ['es2022'], outfile: 'dist/assets/main.js', jsx: 'automatic',
  define: {'process.env.NODE_ENV': '"production"'}, legalComments: 'linked',
  sourcemap: false, metafile: false,
});
await copyFile('index.html', 'dist/index.html');
