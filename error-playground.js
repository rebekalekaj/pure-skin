const log = console.log;

const sum = (a, b) => {
    if(a && b) {
        return a + b;
    }
    throw new Error('Invalid arguments');
}

log(sum(1));
