from storage import load_template_file

def render_invoice(request_dict):
    template_name = request_dict.get('tpl', 'default.html')
    # Directly forwards user input to storage layer
    content = load_template_file('/srv/templates', template_name)
    return content
