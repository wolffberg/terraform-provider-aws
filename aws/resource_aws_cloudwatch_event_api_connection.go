package aws

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	events "github.com/aws/aws-sdk-go/service/cloudwatchevents"
	"github.com/hashicorp/aws-sdk-go-base/tfawserr"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/keyvaluetags"
	"github.com/terraform-providers/terraform-provider-aws/aws/internal/service/cloudwatchevents/finder"
)

func resourceAwsCloudWatchEventConnection() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsCloudWatchEventConnectionCreate,
		Read:   resourceAwsCloudWatchEventConnectionRead,
		Update: resourceAwsCloudWatchEventConnectionUpdate,
		Delete: resourceAwsCloudWatchEventConnectionDelete,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"name": {
				Type:          schema.TypeString,
				Required:      true,
				ForceNew:      true,
				ConflictsWith: []string{"name_prefix"},
				ValidateFunc:  validateCloudWatchEventConnectionName,
			},
			"description": {
				Type:         schema.TypeString,
				Optional:     true,
				Computed:     true,
				ValidateFunc: validation.StringLenBetween(0, 512),
			},
			"basic_auth": {
				Type:          schema.TypeSet,
				Optional:      true,
				Computed:      true,
				ConflictsWith: []string{"oauth_client_credentials", "api_key"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"username": {
							Type:     schema.TypeString,
							Required: true,
						},
						"password": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
						},
					},
				},
			},
			"oauth_client_credentials": {
				Type:          schema.TypeSet,
				Optional:      true,
				Computed:      true,
				ConflictsWith: []string{"basic_auth", "api_key"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"authorization_endpoint": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateOpenIdURL,
						},
						"http_method": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validation.StringInSlice([]string{"GET", "POST", "PUT"}, false),
						},
						"client_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"client_secret": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
						},
						"http_parameters": {
							Type:     schema.TypeSet,
							Optional: true,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"header": {
										Type:     schema.TypeList,
										Optional: true,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"key": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
												"secret": {
													Type:     schema.TypeBool,
													Required: true,
												},
											},
										},
									},
									"body": {
										Type:     schema.TypeList,
										Optional: true,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"key": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
												"secret": {
													Type:     schema.TypeBool,
													Required: true,
												},
											},
										},
									},
									"query": {
										Type:     schema.TypeList,
										Optional: true,
										Computed: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"key": {
													Type:     schema.TypeString,
													Required: true,
												},
												"value": {
													Type:     schema.TypeString,
													Required: true,
												},
												"secret": {
													Type:     schema.TypeBool,
													Required: true,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			"api_key": {
				Type:          schema.TypeList,
				Optional:      true,
				Computed:      true,
				ConflictsWith: []string{"basic_auth", "oauth_client_credentials"},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"key_name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"key_value": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
						},
					},
				},
			},
			"invocation_http_parameters": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"header": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:     schema.TypeString,
										Required: true,
									},
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
									"secret": {
										Type:     schema.TypeBool,
										Required: true,
									},
								},
							},
						},
						"body": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:     schema.TypeString,
										Required: true,
									},
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
									"secret": {
										Type:     schema.TypeBool,
										Required: true,
									},
								},
							},
						},
						"query": {
							Type:     schema.TypeList,
							Optional: true,
							Computed: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"key": {
										Type:     schema.TypeString,
										Required: true,
									},
									"value": {
										Type:     schema.TypeString,
										Required: true,
									},
									"secret": {
										Type:     schema.TypeBool,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
			"arn": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourceAwsCloudWatchEventConnectionCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cloudwatcheventsconn

	name := d.Get("name").(string)

	input, err := buildCreateConnectionInputStruct(d, name)
	if err != nil {
		return fmt.Errorf("Creating CloudWatch Events API Connection failed: %w", err)
	}

	log.Printf("[DEBUG] Creating CloudWatch API Connection: %s", input)

	var out *events.CreateConnectionOutput
	out, err = conn.CreateConnection(input)
	if err != nil {
		return fmt.Errorf("Creating CloudWatch API Connection failed: %w", err)
	}

	d.SetId(name)

	log.Printf("[INFO] CloudWatch API Connection (%s) created", aws.StringValue(out.ConnectionArn))

	return resourceAwsCloudWatchEventConnectionRead(d, meta)
}

func resourceAwsCloudWatchEventConnectionRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cloudwatcheventsconn
	ignoreTagsConfig := meta.(*AWSClient).IgnoreTagsConfig

	out, err := finder.ConnectionByID(conn, d.Id())
	if tfawserr.ErrCodeEquals(err, events.ErrCodeResourceNotFoundException) {
		log.Printf("[WARN] Removing CloudWatch API Connection (%s) because it's gone.", d.Id())
		d.SetId("")
		return nil
	}
	if err != nil {
		return fmt.Errorf("error reading CloudWatch API Connection (%s): %w", d.Id(), err)
	}
	log.Printf("[DEBUG] Found Event Rule: %s", out)

	d.Set("name", out.Name)
	d.Set("description", out.Description)

	switch *out.AuthorizationType {
	case events.ConnectionAuthorizationTypeBasic:
		d.Set("basic_auth", flattenApiConnectionBasicAuth(out.AuthParameters.BasicAuthParameters))
	case events.ConnectionAuthorizationTypeOauthClientCredentials:
		d.Set("oauth_client_credentials", flattenApiConnectionOAuth(out.AuthParameters.OAuthParameters))
	case events.ConnectionAuthorizationTypeApiKey:
		d.Set("api_key", flattenApiConnectionApiKey)
	}

	arn := aws.StringValue(out.ConnectionArn)
	d.Set("arn", arn)

	tags, err := keyvaluetags.CloudwatcheventsListTags(conn, arn)

	if err != nil {
		return fmt.Errorf("error listing tags for CloudWatch API Connection (%s): %w", arn, err)
	}

	if err := d.Set("tags", tags.IgnoreAws().IgnoreConfig(ignoreTagsConfig).Map()); err != nil {
		return fmt.Errorf("error setting tags: %w", err)
	}

	return nil
}

func resourceAwsCloudWatchEventConnectionUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cloudwatcheventsconn

	name := d.Get("name").(string)

	input, err := buildUpdateConnectionInputStruct(d, name)
	if err != nil {
		return fmt.Errorf("Updating CloudWatch API Connection (%s) failed: %w", name, err)
	}

	log.Printf("[DEBUG] Updating CloudWatch API Connection: %s", input)
	_, err = conn.UpdateConnection(input)
	if err != nil {
		return fmt.Errorf("Updating CloudWatch API Connection (%s) failed: %w", name, err)
	}

	return resourceAwsCloudWatchEventConnectionRead(d, meta)
}

func resourceAwsCloudWatchEventConnectionDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).cloudwatcheventsconn

	name := d.Get("name").(*string)

	input := &events.DeleteConnectionInput{
		Name: name,
	}

	_, err := conn.DeleteConnection(input)

	if err != nil {
		return fmt.Errorf("error deleting CloudWatch API Connection (%s): %w", d.Id(), err)
	}

	return nil
}

func flattenApiConnectionBasicAuth(c *events.ConnectionBasicAuthResponseParameters) interface{} {
	r := make(map[string]interface{})
	r["username"] = c.Username
	return r
}

func flattenApiConnectionOAuth(p *events.ConnectionOAuthResponseParameters) interface{} {
	r := make(map[string]interface{})

	r["authorization_endpoint"] = p.AuthorizationEndpoint
	r["client_id"] = p.ClientParameters.ClientID
	r["http_method"] = p.HttpMethod
	r["http_parameters"] = flattenApiConnectionHttpParameters(p.OAuthHttpParameters)
	return r
}

func flattenApiConnectionApiKey(c *events.ConnectionApiKeyAuthResponseParameters) interface{} {
	r := make(map[string]interface{})
	r["key_name"] = c.ApiKeyName
	return r
}

type ApiConnectionHttpParameter struct {
	key    string
	secret bool
}

func flattenApiConnectionHttpParameters(ps *events.ConnectionHttpParameters) []map[string]interface{} {
	var r []map[string]interface{}

	for _, v := range ps.HeaderParameters {
		m := make(map[string]interface{})
		m["header"] = ApiConnectionHttpParameter{*v.Key, *v.IsValueSecret}
		r = append(r, m)
	}

	for _, v := range ps.BodyParameters {
		m := make(map[string]interface{})
		m["body"] = ApiConnectionHttpParameter{*v.Key, *v.IsValueSecret}
		r = append(r, m)
	}

	for _, v := range ps.QueryStringParameters {
		m := make(map[string]interface{})
		m["query"] = ApiConnectionHttpParameter{*v.Key, *v.IsValueSecret}
		r = append(r, m)
	}
	return r
}

func buildCreateConnectionInputStruct(d *schema.ResourceData, name string) (*events.CreateConnectionInput, error) {
	input := events.CreateConnectionInput{
		Name: aws.String(name),
	}

	if v, ok := d.GetOk("description"); ok {
		description := v.(string)
		input.SetDescription(description)
	}

	if v, ok := d.GetOk("invocation_http_parameters"); ok {
		input.AuthParameters.SetInvocationHttpParameters(buildConnectionHttpParametersStruct(v))
	}

	var authType string
	var authRequestParams events.CreateConnectionAuthRequestParameters
	if v, ok := d.GetOk("basic_auth"); ok {
		authType = events.ConnectionAuthorizationTypeBasic
		auth := v.(interface{}).(map[string]interface{})
		params := events.CreateConnectionBasicAuthRequestParameters{
			Username: auth["username"].(*string),
			Password: auth["password"].(*string),
		}
		authRequestParams.SetBasicAuthParameters(&params)
	}

	if v, ok := d.GetOk("oauth_client_credentials"); ok {
		authType = "OAUTH_CLIENT_CREDENTIALS"
		authType = events.ConnectionAuthorizationTypeOauthClientCredentials
		auth := v.(interface{}).(map[string]interface{})
		params := events.CreateConnectionOAuthRequestParameters{
			AuthorizationEndpoint: auth["authorization_endpoint"].(*string),
			HttpMethod:            auth["http_method"].(*string),
			ClientParameters: &events.CreateConnectionOAuthClientRequestParameters{
				ClientID:     auth["client_id"].(*string),
				ClientSecret: auth["client_secret"].(*string),
			},
		}

		if p, ok := auth["http_parameters"]; ok {
			params.SetOAuthHttpParameters(buildConnectionHttpParametersStruct(p))
		}
		authRequestParams.SetOAuthParameters(&params)
	}

	if v, ok := d.GetOk("api_key"); ok {
		authType = events.ConnectionAuthorizationTypeApiKey
		auth := v.(interface{}).(map[string]interface{})
		params := events.CreateConnectionApiKeyAuthRequestParameters{
			ApiKeyName:  auth["key_name"].(*string),
			ApiKeyValue: auth["key_value"].(*string),
		}
		authRequestParams.SetApiKeyAuthParameters(&params)
	}
	input.SetAuthorizationType(authType)
	input.SetAuthParameters(&authRequestParams)

	return &input, nil
}

func buildUpdateConnectionInputStruct(d *schema.ResourceData, name string) (*events.UpdateConnectionInput, error) {
	input := events.UpdateConnectionInput{
		Name: aws.String(name),
	}

	if v, ok := d.GetOk("description"); ok {
		description := v.(string)
		input.SetDescription(description)
	}

	if v, ok := d.GetOk("invocation_http_parameters"); ok {
		input.AuthParameters.SetInvocationHttpParameters(buildConnectionHttpParametersStruct(v))
	}

	var authType string
	var authRequestParams events.UpdateConnectionAuthRequestParameters
	if v, ok := d.GetOk("basic_auth"); ok {
		authType = events.ConnectionAuthorizationTypeBasic
		auth := v.(interface{}).(map[string]interface{})
		params := events.UpdateConnectionBasicAuthRequestParameters{
			Username: auth["username"].(*string),
			Password: auth["password"].(*string),
		}
		authRequestParams.SetBasicAuthParameters(&params)
	}

	if v, ok := d.GetOk("oauth_client_credentials"); ok {
		authType = "OAUTH_CLIENT_CREDENTIALS"
		authType = events.ConnectionAuthorizationTypeOauthClientCredentials
		auth := v.(interface{}).(map[string]interface{})
		params := events.UpdateConnectionOAuthRequestParameters{
			AuthorizationEndpoint: auth["authorization_endpoint"].(*string),
			HttpMethod:            auth["http_method"].(*string),
			ClientParameters: &events.UpdateConnectionOAuthClientRequestParameters{
				ClientID:     auth["client_id"].(*string),
				ClientSecret: auth["client_secret"].(*string),
			},
		}

		if p, ok := auth["http_parameters"]; ok {
			params.SetOAuthHttpParameters(buildConnectionHttpParametersStruct(p))
		}
		authRequestParams.SetOAuthParameters(&params)
	}

	if v, ok := d.GetOk("api_key"); ok {
		authType = events.ConnectionAuthorizationTypeApiKey
		auth := v.(interface{}).(map[string]interface{})
		params := events.UpdateConnectionApiKeyAuthRequestParameters{
			ApiKeyName:  auth["key_name"].(*string),
			ApiKeyValue: auth["key_value"].(*string),
		}
		authRequestParams.SetApiKeyAuthParameters(&params)
	}
	input.SetAuthorizationType(authType)
	input.SetAuthParameters(&authRequestParams)

	return &input, nil
}

func buildConnectionHttpParametersStruct(p interface{}) *events.ConnectionHttpParameters {
	var h []*events.ConnectionHeaderParameter
	var b []*events.ConnectionBodyParameter
	var q []*events.ConnectionQueryStringParameter

	for _, v := range p.(*schema.Set).List() {
		for t, v := range v.(map[string]interface{}) {
			for _, r := range v.([]interface{}) {
				m := r.(map[string]interface{})

				switch t {
				case "header":
					h = append(h, &events.ConnectionHeaderParameter{
						IsValueSecret: m["secret"].(*bool),
						Key:           m["key"].(*string),
						Value:         m["value"].(*string),
					})
				case "body":
					b = append(b, &events.ConnectionBodyParameter{
						IsValueSecret: m["secret"].(*bool),
						Key:           m["key"].(*string),
						Value:         m["value"].(*string),
					})
				case "query":
					q = append(q, &events.ConnectionQueryStringParameter{
						IsValueSecret: m["secret"].(*bool),
						Key:           m["key"].(*string),
						Value:         m["value"].(*string),
					})
				}
			}
		}
	}

	return &events.ConnectionHttpParameters{
		BodyParameters:        b,
		HeaderParameters:      h,
		QueryStringParameters: q,
	}
}
