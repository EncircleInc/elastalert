import itertools
import json

from datetime import datetime
from urllib import urlencode

import requests

from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger

# slack recommends 20 messages but 100 is their real limit
MAX_ATTACHMENTS = 50

class EncircleSlackAlerter(Alerter):
    required_options = frozenset((
        'encircle_slack_webhook',
        'encircle_slack_channel',
        'encircle_slack_kibana',
        'encircle_slack_phabricator',
    ))

    optional_options = (
        ('encircle_slack_username', 'elastalert'),
        ('encircle_slack_emoji', ':rage:'),
    )

    def __init__(self, rule):
        super(EncircleSlackAlerter, self).__init__(rule)

        for k in self.required_options:
            setattr(self, k, self.rule[k])

        for k, v in self.optional_options:
            setattr(self, k, self.rule.get(k, v))

    def alert(self, matches):
        matches = list(matches)
        for i in range(0, len(matches), MAX_ATTACHMENTS):
            self.alert_chunk(matches[i:i+MAX_ATTACHMENTS])

    def alert_chunk(self, matches):
        attachments = []
        for match in matches:
            attachments.append({
                'author_name': self.format_author_name(match),
                'title': self.format_title(match),
                'title_link': self.format_title_link(match),
                'fields': self.format_fields(match),
                'ts': self.format_timestamp(match),
                'color': 'danger',
            })

        payload = {
            'username': self.encircle_slack_username,
            'channel': self.encircle_slack_channel,
            'icon_emoji': self.encircle_slack_emoji,
            'attachments': attachments,
        }

        try:
            response = requests.post(
                self.encircle_slack_webhook,
                data=json.dumps(payload, cls=DateTimeEncoder),
                headers={'content-type': 'application/json'},
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            raise EAException("Error posting to slack: %s" % e)
        elastalert_logger.info("Alert sent to Slack")

    def format_author_name(self, match):
        configuration = match.get('configuration')
        if configuration is None:
            return None

        parts = ', '.join(itertools.chain(
            (configuration.get('script'),),
            ("{}={}".format(k, v) for k, v in configuration.items() if k not in ('host', 'script')),
        ))

        return '{} ({})'.format(configuration.get('host'), parts)

    def format_title(self, match):
        return match.get('message', 'Kibana URL')

    def format_title_link(self, match):
        return "{kibana}/app/kibana#/doc/logstash-*/{index}/{type}?id={id}".format(
            kibana=self.encircle_slack_kibana,
            index=match['_index'],
            type=match['_type'],
            id=match['_id'],
        )

    def format_fields(self, match):
        fields = [{
            'title': 'Phabricator',
            'value': '<{phabricator}?{args}|Create task>'.format(
                phabricator=self.encircle_slack_phabricator,
                args=urlencode({
                    'title': self.format_title(match),
                    'description': self.format_title_link(match),
                }),
            ),
            'short': True,
        }]

        user_email = match.get('params', {}).get('auth', {}).get('user_email')
        if user_email is not None:
            fields.append({
                'title': 'User Email',
                'value': user_email,
                'short': True,
            })

        return fields

    def format_timestamp(self, match):
        dt = datetime.strptime(match['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
        return (dt - datetime(1970, 1, 1)).total_seconds()

    def get_info(self):
        return {
            'type': '.'.join((__name__, self.__class__.__name__)),
        }
