#!/usr/bin/env python3
# encoding: utf-8

'''
A Cortex Analyzer that retrieves results from a local CIF server
'''

from cifsdk.client.http import HTTP as Client
from cortexutils.analyzer import Analyzer


class CIFLookup(Analyzer):
    def __init__(self):
        # Bootstrap our ancestor
        Analyzer.__init__(self)
        # Pull the API token from the application.conf config section
        self.tokens = self.getParam('config.tokens',
                                    None,
                                    'API key is missing')
        # Pull the remote CIF URL from the application.conf config section
        self.remotes = self.getParam('config.remotes',
                                     None,
                                     'Remote CIF host is missing')
        # Set the max results to return from the application.conf config section
        self.limit = self.getParam('config.limit',
                                   None,
                                   'Limit parameter missing')
        # Set whether to verify TLS from the application.conf config section
        self.verify = self.getParam('config.verify',
                                    None,
                                    'Verify parameter missing')
        # Run through the CIF URLs and tokens and pair them into one list
        self.cif_hosts = []
        if len(self.tokens) == len(self.remotes):
            while len(self.remotes):
                remote = self.remotes.pop()
                token = self.tokens.pop()
                cif_host = {'remote': remote, 'token': token}
                self.cif_hosts.append(cif_host)
        else:
            self.error('CIF host/API key pairing is incorrect')

    def summary(self, raw):
        # raw is the json that's returned in the report

        taxonomies = []
        level = 'suspicious'
        namespace = 'CIFLookup'
        # First, a count total results
        tag_count = len(raw['CIF'])
        predicate = 'TotalCount'
        value = tag_count
        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value))

        # Now for each provider:tags
        for result in raw['CIF']:
            tag_list = ''
            for tag in result['tags']:
                tag_list += tag + ','
            provider = result['provider']
            predicate = 'Provider:Tags'
            value = '{0} : {1}'.format(provider, tag_list)
            if value:
                taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {'taxonomies': taxonomies}

    def search_cif(self, indicator):
        '''
        :param indicator: one of domain, fqdn, or hash
        :return: dictionary of results
        '''

        results = []
        for cif_host in self.cif_hosts:
            cli = Client(token=cif_host['token'],
                         remote=cif_host['remote'],
                         verify_ssl=self.verify)
            filters = {
                'indicator': indicator,
                'limit': self.limit,
                'nolog': '1'
            }
            results += cli.indicators_search(filters=filters)

        return results

    def run(self):
        '''
        Run the analysis here
        '''
        Analyzer.run(self)

        if self.data_type in ['ip', 'domain', 'fqdn', 'hash']:
            try:

                # Just get some json, using the user input as the seach query
                cif = self.search_cif(self.getData())

                # This gets put back to the summary report object
                self.report({
                    'CIF': cif
                })

            except ValueError as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    CIFLookup().run()
