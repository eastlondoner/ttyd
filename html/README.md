## Prerequisites

> **NOTE:** yarn v2 is required.

Install [Yarn](https://yarnpkg.com/getting-started/install), and run: `yarn install`.

## Development

1. Start ttyd: `ttyd bash`
2. Start the dev server: `yarn run start`

**Testing Shared PTY Mode:**
1. Start ttyd with shared PTY enabled: `ttyd -Q -W bash`
2. Start the dev server: `yarn run start`
3. Open multiple browser tabs to `http://localhost:8080` to test multi-client behavior

## Publish

Run `yarn run build`, this will compile the inlined html to `../src/html.h`.
