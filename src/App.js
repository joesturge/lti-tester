import React from "react";
import OAuth from "oauth-1.0a";
import crypto from "crypto";
import Joi from "joi";

const ltiData = {
  lti_version: "LTI-1p0",
  lti_message_type: "basic-lti-launch-request",
  resource_link_id: "resource_link_ID"
};

const App = () => {

  const submitRef = React.useRef();

  const [consumerKey, setConsumerKey] = React.useState(localStorage.getItem("consumerKey") || null);
  const [consumerSecret, setConsumerSecret] = React.useState(localStorage.getItem("consumerSecret") || null);
  const [url, setUrl] = React.useState(localStorage.getItem("url") || null);
  const [additional, setAdditional] = React.useState(JSON.parse(localStorage.getItem("additional")) || {});
  const [rememberSecret, setRememberSecret] = React.useState(localStorage.getItem("rememberSecret") === "true");
  const [request, setRequest] = React.useState(null);
  const [error, setError] = React.useState(null);

  const initialAdditional = () => additional ? Object.keys(additional).map(key => `${key}=${additional[key]}`).join("\n") : "";

  const handleSubmit = React.useCallback(e => {
    e.preventDefault();
    const rawConsumerKey = e.target.consumerKey?.value;
    const rawConsumerSecret = e.target.consumerSecret?.value;
    const rawUrl = e.target.url?.value;
    const rawAdditional = e.target.additional?.value;
    const rawRememberSecret = Boolean(e.target.rememberSecret?.checked);

    if (Boolean(Joi.string().uri().validate(rawUrl).error)) {
      setError("Invalid URL");
      return;
    }

    if (!Boolean(rawConsumerKey)) {
      setError("Consumer Key required");
      return;
    }

    if (!Boolean(rawConsumerSecret)) {
      setError("Consumer Secret required");
      return;
    }

    if (Boolean(Joi.string().pattern(/^(.*=.*\n?)+$/).allow("", null).validate(rawAdditional).error)) {
      setError("Invalid Fields");
      return;
    }

    const parsedAdditional = Boolean(rawAdditional) ? rawAdditional.split(/\r?\n/).reduce((prev, line) => ({...prev, [line.split("=")[0]]: line.split("=")[1]}), {}) : null;

    setError(null);
    setConsumerKey(rawConsumerKey);
    setConsumerSecret(rawConsumerSecret);
    setUrl(rawUrl);
    setAdditional(parsedAdditional);
    setRememberSecret(rawRememberSecret);
    
    localStorage.setItem("consumerKey", rawConsumerKey);
    localStorage.setItem("url", rawUrl);
    localStorage.setItem("additional", JSON.stringify(parsedAdditional));
    localStorage.setItem("rememberSecret", rawRememberSecret);
    if (rawRememberSecret) {
      localStorage.setItem("consumerSecret", rawConsumerSecret);
    } else {
      localStorage.removeItem("consumerSecret")
    }

  }, []);

  const handleFieldsUpdate = () => {
    const oauth = OAuth({
      consumer: {
        key: consumerKey,
        secret: consumerSecret,
      },
      signature_method: "HMAC-SHA1",
      hash_function(base_string, key) {
        return crypto.createHmac("sha1", key).update(base_string).digest("base64");
      },
    });

    setRequest(oauth.authorize({
      url: url,
      method: "POST",
      data: {
        ...additional,
        ...ltiData
      },
    }));
  }
  React.useEffect(handleFieldsUpdate, [consumerKey, consumerSecret, url, additional]);

  const handleRequestUpdate = () => {
    if (Boolean(request)) {
      submitRef.current.click();
    }
  }
  React.useEffect(handleRequestUpdate, [request]);

  return (
    <React.Fragment>
      <form onSubmit={handleSubmit} autocomplete="off" style={{width: "70%"}}>
        <label htmlFor="url">URL</label><br/>
        <input style={{width: "100%"}} type="text" id="url" name="url" defaultValue={url}/><br/>
        <label htmlFor="consumerKey">Consumer key</label><br/>
        <input style={{width: "100%"}} type="text" id="consumerKey" name="consumerKey" defaultValue={consumerKey}/><br/>
        <label htmlFor="consumerSecret">Consumer secret</label><br/>
        <input style={{width: "100%"}} type="password" id="consumerSecret" name="consumerSecret" defaultValue={consumerSecret}/><br/>
        <input type="checkbox" id="rememberSecret" name="rememberSecret" defaultChecked={rememberSecret}/>
        <label htmlFor="rememberSecret">Remember Secret?</label><br/><br/>
        <label htmlFor="additional">Fields<br /><small>key1=value1<br/>key2=value2<br/>etc...</small></label><br/>
        <textarea style={{width: "100%"}} name="additional" defaultValue={initialAdditional()}/><br/>
        <button type="submit">Submit</button> 
      </form> 
      {Boolean(error) && <p style={{color: "red"}}>{error}</p>}
      <form
        id="ltiForm"
        target="ltiFrame"
        action={url}
        method="POST"
        hidden
      >
        {request && Object.keys(request).map((name) => (
          <input hidden key={name} name={name} value={request[name]} readOnly />
        ))}
        <button type="submit" ref={submitRef}>Submit</button>
      </form>
      <br/>
      <iframe
        title="ltiFrame"
        name="ltiFrame"
        style={{ display: "block", height: "50vh", width: "100%" }}
      >
        Your browser does not support inline frames.
      </iframe>
    </React.Fragment>
  );
};

export default App;
