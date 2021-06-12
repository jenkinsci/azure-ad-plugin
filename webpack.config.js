const path = require('path');

module.exports = {
  entry: './src/main/frontend',
  // enable source maps for debugging webpack output
  devtool: 'source-map',
  module: {
    rules: [
      {
        test: /\.tsx?$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
      {
        test: /\.js$/,
        enforce: 'pre',
        loader: 'source-map-loader',
      },
    ],
  },
  resolve: {
    extensions: ['.tsx', '.ts', '.js'],
  },
  output: {
    filename: 'azure-ad-bundle.js',
    path: path.resolve(__dirname, 'src/main/webapp/js'),
  },
};

