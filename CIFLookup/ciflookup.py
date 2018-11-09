#!/usr/bin/env python3
# encoding: utf-8

"""
A Cortex Analyzer that retrieves results from a local CIF server
"""

from cifsdk.client.http import HTTP as Client
from cortexutils.analyzer import Analyzer


class CIFLookup(Analyzer):
    def __init__(self):
        # Bootstrap our ancestor
        Analyzer.__init__(self)
        # Pull the API token from the application.conf config section
        self.token = self.getParam('config.token',
                                   None,
                                   'API key is missing'
                                   )
        # Pull the remote CIF URL from the application.conf config section
        self.remote = self.getParam('config.remote',
                                    None,
                                    'Remote CIF host is missing'
                                    )
        # Set the max results to return from the application.conf config section
        self.limit = self.getParam('config.limit',
                                    None,
                                    'Limit parameter missing'
                                    )
        # Set whether to verify TLS from the application.conf config section
        self.verify = self.getParam('config.verify',
                                    None,
                                   'Verify parameter missing'
                                   )
        # We don't want to extract observables for Hive from this
        self.auto_extract = False

    def summary(self, raw):
        """
        'raw' is the json that's returned in the report
        """
        taxonomies = [ ]
        level = "info"
        namespace = "CIFLookup"
        # First, a count total results
        tcount = len(raw[ 'CIF' ])
        predicate = "Total Count"
        value = "{0}",format(tcount)
        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, value))

        # Now for each provider:tags
        if tcount > 0:
            for result in raw[ 'CIF']:
                tlist = ""
                for t in result['tags']:
                    tlist += t + ","
                provider = result['provider']
            predicate = "Provider:Tags"
            value = "{0} : {1}".format(provider,tlist)
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def search_cif(self, indicator):
        """

        :param indicator: one of domain, fqdn, or hash
        :return: dictionary of results
        """
        cli = Client(token=self.token,
                     remote=self.remote,
                     verify_ssl=self.verify
                     )
        filters = {
            "indicator": indicator,
            "limit": self.limit
        }

        ret = cli.indicators_search(filters=filters)

        return ret

    def run(self):
        """
        Run the analysis here
        """
        Analyzer.run(self)

        if self.data_type in ['ip', "domain", "fqdn", "hash"]:
            try:

                ## Just get some json, using the user input as the seach query
                cif = self.search_cif(self.getData())

                ## This gets put back to the summary report object
                self.report({
                    'CIF': cif
                })

            except ValueError as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    CIFLookup().run()
