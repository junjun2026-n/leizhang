from pathlib import Path

from playwright.sync_api import sync_playwright


def test_web_desktop_input_and_connection_error_remain_visible():
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(channel='msedge', headless=True)
        page = browser.new_page()
        page.set_content('<main id="desktop"></main>')
        page.evaluate('''() => {
            window.node = (tag,text,style) => {
                const element=document.createElement(tag);
                if(text!==undefined)element.textContent=text;
                if(style)element.className=style;
                return element;
            };
            window.button = (text,callback) => {
                const element=node('button',text);element.onclick=callback;return element;
            };
            window.WebSocket = class {
                static OPEN=1;
                constructor(){this.readyState=1;this.messages=[];window.connection=this;}
                send(data){this.messages.push(JSON.parse(data));}
                close(){this.onclose?.();}
            };
        }''')
        page.add_script_tag(path=str(Path(__file__).resolve().parents[1]/'static/vnc.js'))
        page.evaluate('''() => {
            window.view=nativeVncView(document.getElementById('desktop'),{websocket:'/desktop',ticket:'test'});
            connection.onopen();
            connection.onmessage({data:JSON.stringify({type:'ready',width:800,height:600,message:'ready'})});
        }''')
        assert page.get_by_role('button',name='全屏桌面').is_visible()
        page.get_by_alt_text('VNC 远程桌面').press('ArrowLeft')
        assert page.evaluate('connection.messages.some(message=>message.type==="key" && message.key===0xff51 && message.down)')
        page.evaluate('''() => {
            connection.onmessage({data:JSON.stringify({type:'closed',message:'target authentication failed'})});
            connection.onclose();
        }''')
        assert page.get_by_text('target authentication failed',exact=True).is_visible()
        page.evaluate('view.close()')
        assert page.locator('.vnc-desktop').count()==0
        browser.close()
