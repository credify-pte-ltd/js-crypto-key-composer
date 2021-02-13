import del from 'rollup-plugin-delete';
import pkg from './package.json';
import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';

export default [
    {
        input: 'src/index.js',
        output: [
            { file: pkg.main, format: 'cjs', sourcemap: true },
        ],
        plugins: [
            del({ targets: ['dist/*'] }),
            json(),
            commonjs({
                include: 'node_modules/**',
            }),
            resolve(),
        ],
        external: Object.keys(pkg.dependencies || {}),
    },
];
