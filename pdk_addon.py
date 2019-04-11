import json
import time

import requests

from mitmproxy import ctx

class PDKListener:
    def __init__(self, upload_url):
        self.upload_url = upload_url
        self.pending_visits = []

    def request(self, flow):
        visit = {}
        visit['url'] = flow.request.url
        visit['client_ip'] = flow.client_conn.address[0]
        visit['headers'] = dict(flow.request.headers)
        visit['headers'] = dict(flow.request.headers)
        visit['date'] = time.time() * 1000
        
        pdk_metadata = {
            'source': visit['client_ip'],
            'generator-id': 'pdk-mitmproxy-visit',
            'timestamp': visit['date'] / 1000
        }
        
        if 'user-agent' in visit['headers']:
            pdk_metadata['generator'] = 'mitmproxy: ' + visit['headers']['user-agent']
        else:
            pdk_metadata['generator'] = 'mitmproxy: Unknown User Agent'
            
        visit['passive-data-metadata'] = pdk_metadata
        
        self.pending_visits.append(visit)

    def clientdisconnect(self, layer):
        self.transmit_visits()
            
    def transmit_visits(self):
        to_transmit = self.pending_visits
        
        self.pending_visits = []
        
        if to_transmit:
            r = requests.post(self.upload_url, data={'payload': json.dumps(to_transmit)})
            
            if (r.status_code >= 200 and r.status_code < 300) is False:
                ctx.log.info("FAILED UPLOADING. STATUS: %d" % r.status_code)
                self.pending_visits.extend(to_transmit)
            else:
                ctx.log.info('UPLOAD SUCCESSFUL')

addons = [
    PDKListener('https://my-site.org/data/add-bundle.json')
]
