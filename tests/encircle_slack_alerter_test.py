import json
import urllib

import mock

from elastalert.config import load_modules

from encircle_slack_alerter import EncircleSlackAlerter

def test_encircle_slack_alerter():
    rule = {
        'name': 'Test Rule',
        'type': 'any',
        'encircle_slack_webhook': 'http://slack.example.com',
        'encircle_slack_channel': 'example-channel',
        'encircle_slack_kibana': 'http://kibana.example.com',
        'encircle_slack_phabricator': 'http://phabricator.example.com',
        'alert': [],
    }
    load_modules(rule)

    alert = EncircleSlackAlerter(rule)

    matches = [{
        "_index": "logstash-1970.01.01",
        "_type": "logstash",
        "_id": "AAAAA",
        "@timestamp": "1970-01-01T00:00:00.000Z",
        "configuration": {
            "port": 8888,
            "script": "webserver",
            "host": "host1.example.com",
        },
        "message": "Test log message",
        "params": {
            "auth": {
                "user_email": "alice@example.com",
            },
        },
    }]

    with mock.patch('requests.post') as mock_post_request:
        alert.alert(matches)

    mock_post_request.assert_called_once_with(
        rule['encircle_slack_webhook'],
        data=mock.ANY,
        headers={'content-type': 'application/json'},
    )

    expected_data = {
        'username': 'elastalert',
        'channel': 'example-channel',
        'icon_emoji': ':rage:',
        'attachments': [{
            'author_name': 'host1.example.com (webserver, port=8888)',
            'title': 'Test log message',
            'title_link': 'http://kibana.example.com/app/kibana#/doc/logstash-*/logstash-1970.01.01/logstash?id=AAAAA',
            'fields': [{
                'title': 'Phabricator',
                'value': '<http://phabricator.example.com?{args}|Create task>'.format(
                    args=urllib.urlencode({
                        'title': 'Test log message',
                        'description': 'http://kibana.example.com/app/kibana#/doc/logstash-*/logstash-1970.01.01/logstash?id=AAAAA',
                    }),
                ),
                'short': True,
            }, {
                'title': 'User Email',
                'value': 'alice@example.com',
                'short': True,
            }],
            'ts': 0,
            'color': 'danger',
        }],
    }

    assert expected_data == json.loads(mock_post_request.call_args_list[0][1]['data'])
