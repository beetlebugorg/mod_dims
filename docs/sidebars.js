/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  docs: [
    'introduction',
    'installation',
    {
      type: 'category',
      label: 'Endpoints',
      link: {type: 'doc', id: 'endpoints/index'},
      items: ['endpoints/dims5', 'endpoints/dims4', 'endpoints/dims3', 'endpoints/status', 'endpoints/metrics', 'endpoints/local'],
    },
    {
      type: 'category',
      label: 'Operations',
      link: {type: 'doc', id: 'operations/index'},
      items: [
        {
          type: 'category',
          label: 'Transformations',
          items: [
            'operations/transformations/resize',
            'operations/transformations/crop',
            'operations/transformations/thumbnail',
            'operations/transformations/rotate',
            'operations/transformations/flipflop',
            'operations/transformations/legacy',
          ],
        },
        {
          type: 'category',
          label: 'Adjustments',
          items: [
            'operations/adjustments/brightness',
            'operations/adjustments/sharpen',
            'operations/adjustments/grayscale',
            'operations/adjustments/sepia',
            'operations/adjustments/invert',
            'operations/adjustments/autolevel',
          ],
        },
        {
          type: 'category',
          label: 'Output',
          items: [
            'operations/output/format',
            'operations/output/quality',
            'operations/output/strip',
          ],
        },
        {type: 'category', label: 'Special', items: ['operations/special/watermark']},
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      link: {type: 'doc', id: 'configuration/index'},
      items: [
        'configuration/clients',
        'configuration/image-sources',
        'configuration/cache-control',
        'configuration/output',
        'configuration/resources',
        'configuration/metrics',
      ],
    },
  ],
};

export default sidebars;
