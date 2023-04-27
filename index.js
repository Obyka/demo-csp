const express = require('express')
const helmet = require('./middleware/helmet')
const bp = require('body-parser')
const { lodashNonce } = require('./middleware/nonces')
const app = express()
const port = 3000
const cspHeader = `content-security-policy`

let crypto
try {
    crypto = require("crypto")
} catch (err) {
    console.log("crypto support is disabled!")
}

app.set("view engine", "ejs")

app.use(bp.json())
app.use(bp.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use((req, res, next) => {
    res.cookie('secret-value', crypto.randomBytes(16).toString("hex"), { maxAge: 900000, httpOnly: false });
    next();
})

app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy-Report-Only',
        "default-src 'self'; report-uri https://en9rq37x0iv25.x.pipedream.net"
    );
    next();
})

app.get('/jsonp', (req, res) => {
    res.set('Content-Type', 'text/html');
    var jsonpCsp = `default-src 'self' https://*.google.com https://*.googleapis.com https://*.twitter.com; style-src 'unsafe-inline'`
    res.setHeader(cspHeader, jsonpCsp)

    res.render("jsonp", { csp: cspHeader + ': ' + jsonpCsp, xss: req.query.xss })
})
app.post('/jsonp', (req, res) => {
    let data = req.body;
    //res.send('Data Received: ' + data.xss);
    res.redirect('/jsonp?xss=' + data.xss);
})

app.get('/nocsp', (req, res) => {
    res.set('Content-Type', 'text/html');
    var noCsp = ``
    res.render("nocsp", { csp: cspHeader + ': ' + noCsp, xss: req.query.xss })
})
app.post('/nocsp', (req, res) => {
    let data = req.body;
    //res.send('Data Received: ' + data.xss);
    res.redirect('/nocsp?xss=' + data.xss);
})

app.get('/inline', (req, res) => {
    res.set('Content-Type', 'text/html');
    var inlineCsp = `default-src 'none'; script-src 'unsafe-inline' style-src 'self';`
    res.setHeader(cspHeader, inlineCsp)


    res.render("unsafe-inline", { csp: cspHeader + ': ' + inlineCsp, xss: req.query.xss })
})
app.post('/inline', (req, res) => {
    let data = req.body;
    //res.send('Data Received: ' + data.xss);
    res.redirect('/inline?xss=' + data.xss);
})

app.get('/selfcsp', (req, res) => {
    res.set('Content-Type', 'text/html');
    var selfCsp = `script-src 'self' shorturl.at; object-src 'none';`
    res.setHeader(cspHeader, selfCsp)
    res.render("self", { csp: cspHeader + ': ' + selfCsp, xss: req.query.xss })
})

app.post('/selfcsp', (req, res) => {
    let data = req.body;
    res.redirect('/selfcsp?xss=' + data.xss);
})

app.get('/noncecsp', (req, res) => {
    var nonceCsp = `default-src 'strict-dynamic' 'nonce-${lodashNonce}'; base-uri 'none'; object-src 'none'; style-src 'self';`
    res.set('Content-Type', 'text/html');
    res.setHeader(cspHeader, nonceCsp)
    res.render("nonce", { ourGenerateNonce: lodashNonce, csp: cspHeader + ': ' + nonceCsp, xss: req.query.xss })
})

app.post('/noncecsp', (req, res) => {
    let data = req.body;
    //res.send('Data Received: ' + data.xss);
    res.redirect('/noncecsp?xss=' + data.xss);
})

app.get('/', (req, res) => {
    var somehtml = '<html>';
    res.set('Content-Type', 'text/html');
    app._router.stack.map(r => {
        if (r.route !== undefined && r.route.path !== undefined && r.route.methods.get !== undefined) {
            console.log(r.route.methods.get)
            somehtml += "<p><a href='" + r.route.path + "'>" + r.route.path + "<p></a>"
        }
    })
    somehtml += "</html>"
    res.send(somehtml)
})

app.get('/redirect', (req, res) => {
    res.set('Content-Type', 'text/html');
    var htmlContent = `<html><body onload="window.location='` + req.query.url + `'"></body></html>`
    res.send(htmlContent)
    //res.redirect(req.query.url)
})

app.listen(port, '0.0.0.0', () => {
    console.log(`Example app listening on port ${port}`)
})

/* Payload JS

nocsp: <script>alert('Psst! I stole your cookie: '.concat(document.cookie))</script>
unsafe-inline: <script>alert('Psst! I stole your cookie: '.concat(document.cookie))</script>
jsonp: <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert('Psst! I stole your cookie: '.concat(document.cookie))""></script>
nonce: <script nonce="6ebac764dfbc9d3c2a0f5cfa51968ec8">alert(11)</script>
*/