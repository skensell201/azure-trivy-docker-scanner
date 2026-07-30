const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

module.exports = {
  entry: { hub: './src/hub/hub.tsx' },
  output: { path: path.join(__dirname, 'dist'), filename: '[name].js', clean: true },
  resolve: { extensions: ['.ts', '.tsx', '.js'] },
  module: {
    rules: [
      { test: /\.tsx?$/, use: { loader: 'ts-loader', options: { compilerOptions: { noEmit: false } } } },
      { test: /\.css$/, use: ['style-loader', 'css-loader'] },
    ],
  },
  plugins: [new HtmlWebpackPlugin({ filename: 'hub.html', template: './src/hub/hub.html', chunks: ['hub'] })],
};
