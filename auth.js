const fs = require('fs');

function useSingleFileAuthState(filePath) {
    let state = {};  // start as empty object

    if (fs.existsSync(filePath)) {
        try {
            state = JSON.parse(fs.readFileSync(filePath, { encoding: 'utf-8' }));
        } catch {
            state = {};  // fallback if JSON malformed
        }
    }

    const saveState = () => {
        fs.writeFileSync(filePath, JSON.stringify(state, null, 2));
    };

    return { state, saveState };
}

module.exports = { useSingleFileAuthState };