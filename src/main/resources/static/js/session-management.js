// OpenID Connect Session Management section 3.1: the RP iframe, written out.
//
// It polls the OP iframe with postMessage and does nothing else. No request reaches the
// authorization server while this runs - that is the whole reason the mechanism exists.
(function () {
    const config = document.getElementById('rp-iframe-config').dataset;
    const opFrame = document.getElementById('op-iframe');
    const log = document.getElementById('session-log');
    const status = document.getElementById('session-status');
    const message = config.clientId + ' ' + config.sessionState;
    const targetOrigin = config.opOrigin;
    let polls = 0;

    function record(text, tone) {
        const row = document.createElement('div');
        row.textContent = new Date().toLocaleTimeString() + '  ' + text;
        if (tone) {
            row.style.color = tone;
        }
        log.prepend(row);
    }

    // Section 3.1: only messages from the OP frame's origin may be processed. Origin alone is not
    // enough when the client and the provider share one, as they do here: everything on this page's
    // origin can post to this window, and plenty does. So the source frame is checked too, and
    // anything that is not one of the three answers the specification defines is ignored rather
    // than mistaken for one.
    window.addEventListener('message', function (event) {
        if (event.origin !== targetOrigin || event.source !== opFrame.contentWindow) {
            return;
        }
        if (event.data !== 'unchanged' && event.data !== 'changed' && event.data !== 'error') {
            return;
        }
        if (event.data === 'unchanged') {
            record('unchanged - the session at the provider is the one we were told about');
            status.textContent = 'unchanged';
            status.style.color = '#2f6f4f';
            return;
        }
        if (event.data === 'changed') {
            record('changed - something happened at the provider. A real client re-authenticates '
                + 'now with prompt=none to find out what.', '#b3261e');
            status.textContent = 'changed';
            status.style.color = '#b3261e';
            return;
        }
        // Section 3.1: on error the client must NOT re-authenticate, or it loops forever.
        record('error - the provider could not make sense of the message. No re-authentication: '
            + 'that is how the loops start.', '#b3261e');
        status.textContent = 'error';
        status.style.color = '#b3261e';
    }, false);

    function poll() {
        polls += 1;
        record('poll ' + polls + ' -> "' + config.clientId + ' <session_state>"');
        opFrame.contentWindow.postMessage(message, targetOrigin);
    }

    opFrame.addEventListener('load', function () {
        record('the provider iframe loaded from ' + targetOrigin);
        poll();
        setInterval(poll, 5000);
    });

    document.getElementById('poll-now').addEventListener('click', function (event) {
        event.preventDefault();
        poll();
    });

    document.getElementById('send-rubbish').addEventListener('click', function (event) {
        event.preventDefault();
        record('sending a message with no session state in it');
        opFrame.contentWindow.postMessage('nonsense-without-a-space', targetOrigin);
    });

    // Changing the state without leaving the page, because that is how it happens in life: the
    // session ends somewhere else and this client goes on holding the value it was given. Reloading
    // here would fetch a session state computed from the new state, and nothing would look wrong.
    document.getElementById('change-state').addEventListener('submit', async function (event) {
        event.preventDefault();
        const form = event.target;
        record('something changed the session at the provider');
        await fetch(form.action, {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: new URLSearchParams(new FormData(form)),
            redirect: 'manual'
        });
        poll();
    });
}());
