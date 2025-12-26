const validator = require('../validator');

test('password validator requires upper and lower and other rules', () => {
    const weak = validator.validatePassword('short');
    expect(weak.ok).toBe(false);

    const noUpper = validator.validatePassword('lowercase1!');
    expect(noUpper.ok).toBe(false);

    const noLower = validator.validatePassword('UPPERCASE1!');
    expect(noLower.ok).toBe(false);

    const good = validator.validatePassword('GoodPass1!');
    expect(good.ok).toBe(true);
});
