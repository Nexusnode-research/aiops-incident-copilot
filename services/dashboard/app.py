
import dash
from dash import dcc, html, Input, Output, State, callback
import pandas as pd
import plotly.express as px
from db import get_incidents, get_incident_details, get_incident_evidence
from copilot import generate_heuristic_brief, generate_ai_brief, generate_splunk_queries
import json

app = dash.Dash(__name__, external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'])
app.title = "AIOps Copilot"

app.layout = html.Div([
    dcc.Store(id='selected-incident-id'),
    html.H1("AIOps Incident Copilot", style={'textAlign': 'center'}),
    
    # Top Bar: Filters
    html.Div([
        html.Label("Time Range:"),
        dcc.Dropdown(
            id='time-filter',
            options=[
                {'label': 'Last 4 Hours', 'value': 4},
                {'label': 'Last 24 Hours', 'value': 24},
                {'label': 'Last 7 Days', 'value': 168}
            ],
            value=24,
            clearable=False,
            style={'width': '200px'}
        ),
        html.Button('Refresh', id='refresh-btn', n_clicks=0),
    ], style={'display': 'flex', 'gap': '20px', 'marginBottom': '20px'}),
    
    html.Div([
        # LEFT: Incident List
        html.Div([
            html.H5("Incidents"),
            dcc.Loading(id="loading-list", children=[
                html.Div(id='incident-list-container')
            ])
        ], style={'width': '30%', 'float': 'left', 'height': '800px', 'overflowY': 'scroll', 'borderRight': '1px solid #ccc', 'paddingRight': '10px'}),
        
        # RIGHT: Details View
        html.Div([
            html.Div(id='incident-details-view', children=[
                html.H3("Select an incident from the list to view details.", style={'color': '#ccc', 'textAlign': 'center', 'marginTop': '100px'})
            ])
        ], style={'width': '68%', 'float': 'right', 'paddingLeft': '10px'})
    ])
])

@callback(
    Output('incident-list-container', 'children'),
    [Input('refresh-btn', 'n_clicks'), Input('time-filter', 'value')]
)
def update_incident_list(n_clicks, hours):
    df = get_incidents(hours=hours)
    
    if df.empty:
        return html.Div("No incidents found in this time range.")
        
    items = []
    for _, row in df.iterrows():
        # Status Color
        st = row['status']
        if st == 'NEW':
            color = 'red'
        elif st == 'CLOSED':
            color = 'green'
        else:
            color = 'orange'
        
        # Safe string formatting
        title_text = "{} (Sev {})".format(row['title'], row['severity'])
        status_text = "Status: {} | Updated: {}".format(row['status'], row['last_update_str'])
        
        item = html.Div([
            html.H6(title_text, style={'margin': '0'}),
            html.P(status_text),
            html.Button("View", id={'type': 'incident-btn', 'index': row['id']}, n_clicks=0)
        ], style={'border': '1px solid ' + color, 'padding': '10px', 'marginBottom': '10px', 'borderRadius': '5px'})
        items.append(item)
        
    return items

@callback(
    [Output('incident-details-view', 'children'),
     Output('selected-incident-id', 'data')],
    [Input({'type': 'incident-btn', 'index': dash.ALL}, 'n_clicks')],
    prevent_initial_call=True
)
def display_incident(n_clicks):
    ctx = dash.callback_context
    if not ctx.triggered:
        return html.Div("Select an incident."), None
        
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    incident_id = json.loads(button_id)['index']
    
    # Fetch Data
    incident = get_incident_details(incident_id)
    signals = get_incident_evidence(incident_id)
    
    if incident is None:
        return html.Div("Error loading incident."), None
        
    # Generate Content
    brief_md = generate_heuristic_brief(incident, signals)
    splunk_queries = generate_splunk_queries(
        incident['root_entity_type'], incident['root_entity_id'], 
        incident['start_time'], incident['last_update_time']
    )
    
    # Charts
    fig = px.histogram(signals, x="event_time", y="severity", title="Signal Severity Over Time")
    
    # Query Buttons
    query_elems = []
    for q in splunk_queries:
        query_elems.append(html.Div([
            html.Strong(q['title']),
            html.Br(),
            dcc.Textarea(value=q['query'], readOnly=True, style={'width': '100%', 'height': '60px'}),
        ], style={'marginBottom': '10px'}))
    
    layout = html.Div([
        html.H2("Incident #{}: {}".format(incident_id, incident['title'])),
        html.Div([
            html.Span("Status: {} ".format(incident['status']), style={'fontWeight': 'bold'}),
            html.Span("| Severity: {} | Score: {}".format(incident['severity'], incident['score'])),
        ]),
        html.Hr(),
        
        # Tabs
        dcc.Tabs([
            dcc.Tab(label='Copilot Brief', children=[
                html.Div([
                    # Heuristic Brief (Always visible initially)
                    html.Div([
                        html.H5("Heuristic Summary"),
                        dcc.Markdown(brief_md)
                    ], style={'marginBottom': '20px', 'borderBottom': '1px solid #eee', 'paddingBottom': '10px'}),
                    
                    # AI Brief Section
                    html.Div([
                        html.H5("AI Analyst Brief"),
                        html.Button("Generate with AI", id="btn-generate-ai", n_clicks=0, style={'marginBottom': '10px'}),
                        dcc.Loading(
                            id="loading-ai",
                            type="default",
                            children=[dcc.Markdown(id="ai-brief-content", children="Click generate to analyze evidence with AI.")]
                        )
                    ]),
                    
                    html.Hr(),
                    html.H4("Splunk Investigation"),
                    html.Div(query_elems)
                ], style={'padding': '20px', 'backgroundColor': '#f9f9f9', 'border': '1px solid #ddd'})
            ]),
            dcc.Tab(label='Evidence Timeline', children=[
                dcc.Graph(figure=fig),
                html.H5("All Evidence"),
                html.Table([
                    html.Thead(html.Tr([html.Th("Time"), html.Th("Signal"), html.Th("Severity"), html.Th("Entity")])),
                    html.Tbody([
                        html.Tr([
                            html.Td(row['time_str']),
                            html.Td(row['signal_name']),
                            html.Td(row['severity']),
                            html.Td(row['entity_id'])
                        ]) for _, row in signals.iterrows()
                    ])
                ], className='u-full-width')
            ])
        ])
    ])
    
    return layout, incident_id

@callback(
    Output("ai-brief-content", "children"),
    Input("btn-generate-ai", "n_clicks"),
    State("selected-incident-id", "data"),
    prevent_initial_call=True
)
def generate_brief_callback(n_clicks, incident_id):
    if not incident_id or n_clicks == 0:
        return dash.no_update
        
    # Fetch fresh data for the AI function
    incident = get_incident_details(incident_id)
    signals = get_incident_evidence(incident_id)
    
    if incident is None:
        return "Error: Could not reload incident data."
        
    return generate_ai_brief(incident, signals)

if __name__ == '__main__':
    # Run on 0.0.0.0 to be accessible if mapped, or localhost
    app.run(host='0.0.0.0', port=8050, debug=False)
